package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// ---------------------------------------------------------------- SPF

var spfQualifiers = map[byte]string{'+': "Pass", '-': "Fail", '~': "SoftFail", '?': "Neutral"}

var spfDescriptions = map[string]string{
	"v":        "SPF version",
	"all":      "Matches everything not matched earlier",
	"include":  "Evaluate another domain's SPF policy",
	"a":        "Match the domain's A/AAAA records",
	"mx":       "Match the domain's MX hosts",
	"ip4":      "Match an IPv4 address or range",
	"ip6":      "Match an IPv6 address or range",
	"ptr":      "Match reverse DNS (deprecated, RFC 7208 §5.5)",
	"exists":   "Match if the domain resolves",
	"redirect": "Use another domain's SPF policy instead",
	"exp":      "Explanation string for failures",
}

// Mechanisms that cost one DNS lookup against the RFC 7208 limit of 10.
var spfLookupTerms = map[string]bool{"include": true, "a": true, "mx": true, "ptr": true, "exists": true, "redirect": true}

type spfTerm struct {
	Qualifier byte
	Name      string
	Value     string
	Modifier  bool
}

func parseSPF(record string) []spfTerm {
	var terms []spfTerm
	for _, f := range strings.Fields(record)[1:] {
		t := spfTerm{Qualifier: '+'}
		if strings.ContainsAny(f[:1], "+-~?") {
			t.Qualifier = f[0]
			f = f[1:]
		}
		if i := strings.IndexAny(f, ":=/"); i >= 0 {
			t.Name, t.Value = strings.ToLower(f[:i]), f[i:]
			if f[i] == '=' {
				t.Modifier = true
			}
			t.Value = strings.TrimLeft(t.Value, ":=")
		} else {
			t.Name = strings.ToLower(f)
		}
		terms = append(terms, t)
	}
	return terms
}

func findSPF(ctx context.Context, res *Resolver, domain string) ([]string, *QueryResult, error) {
	txts, qr, err := res.LookupTXT(ctx, domain)
	if err != nil {
		return nil, qr, err
	}
	var spf []string
	for _, t := range txts {
		if strings.HasPrefix(strings.ToLower(t), "v=spf1 ") || strings.EqualFold(t, "v=spf1") {
			spf = append(spf, t)
		}
	}
	return spf, qr, nil
}

// countSPFLookups recursively counts DNS-querying terms, following
// include: and redirect=.
func countSPFLookups(ctx context.Context, res *Resolver, domain string, depth int, seen map[string]bool) (int, error) {
	if depth > 10 {
		return 0, fmt.Errorf("include depth exceeded")
	}
	if seen[domain] {
		return 0, fmt.Errorf("include loop at %s", domain)
	}
	seen[domain] = true
	recs, _, err := findSPF(ctx, res, domain)
	if err != nil {
		return 0, err
	}
	if len(recs) != 1 {
		return 0, fmt.Errorf("%s has %d SPF records", domain, len(recs))
	}
	n := 0
	for _, t := range parseSPF(recs[0]) {
		if !spfLookupTerms[t.Name] {
			continue
		}
		n++
		if t.Name == "include" || t.Name == "redirect" {
			sub, err := countSPFLookups(ctx, res, strings.ToLower(t.Value), depth+1, seen)
			n += sub
			if err != nil {
				return n, err
			}
		}
	}
	return n, nil
}

func cmdSPF(ctx context.Context, res *Resolver, arg string, out *Result) error {
	domain, err := cleanDomain(arg)
	if err != nil {
		return err
	}
	out.Query = domain
	recs, qr, err := findSPF(ctx, res, domain)
	if err != nil {
		return err
	}
	if !rcodeCheck(out, qr, domain) {
		return nil
	}
	out.Headers = []string{"Prefix", "Type", "Value", "Description"}
	switch len(recs) {
	case 0:
		out.check(StatusFail, "SPF record", "No SPF record found for %s", domain)
		return nil
	case 1:
		out.check(StatusPass, "SPF record", "SPF record found: %s", recs[0])
	default:
		out.check(StatusFail, "Single SPF record", "%d SPF records found; RFC 7208 allows only one (result is PermError)", len(recs))
	}

	terms := parseSPF(recs[0])
	out.Rows = append(out.Rows, []string{"", "v", "spf1", spfDescriptions["v"]})
	var allQual byte
	hasAll, hasRedirect := false, false
	for _, t := range terms {
		prefix := ""
		desc := spfDescriptions[t.Name]
		if desc == "" {
			desc = "Unknown term"
		}
		if !t.Modifier {
			prefix = fmt.Sprintf("%c (%s)", t.Qualifier, spfQualifiers[t.Qualifier])
		}
		out.Rows = append(out.Rows, []string{prefix, t.Name, t.Value, desc})
		switch t.Name {
		case "all":
			hasAll, allQual = true, t.Qualifier
		case "redirect":
			hasRedirect = true
		case "ptr":
			out.check(StatusWarn, "No ptr mechanism", "The ptr mechanism is deprecated and should not be used")
		}
		if desc == "Unknown term" {
			out.check(StatusFail, "Valid syntax", "Unknown SPF term %q", t.Name)
		}
	}

	if len(recs) == 1 {
		n, err := countSPFLookups(ctx, res, domain, 0, map[string]bool{})
		switch {
		case err != nil:
			out.check(StatusFail, "DNS lookups", "Error evaluating includes: %v", err)
		case n > 10:
			out.check(StatusFail, "DNS lookups", "%d DNS lookups exceeds the limit of 10 (PermError)", n)
		case n >= 8:
			out.check(StatusWarn, "DNS lookups", "%d of 10 allowed DNS lookups used", n)
		default:
			out.check(StatusPass, "DNS lookups", "%d of 10 allowed DNS lookups used", n)
		}
	}

	switch {
	case hasAll && allQual == '+':
		out.check(StatusFail, "Restrictive all", "+all allows anyone to send mail as %s", domain)
	case hasAll && allQual == '?':
		out.check(StatusWarn, "Restrictive all", "?all is neutral and provides no protection")
	case hasAll:
		out.check(StatusPass, "Restrictive all", "Record ends with %call", allQual)
	case !hasRedirect:
		out.check(StatusWarn, "Restrictive all", "No all mechanism; default result is Neutral")
	}
	if len(recs[0]) > 255 {
		out.check(StatusInfo, "Record length", "Record is %d characters and split across multiple strings", len(recs[0]))
	}
	return nil
}

// ---------------------------------------------------------------- DMARC

var dmarcDescriptions = map[string]string{
	"v":     "Protocol version",
	"p":     "Policy for the domain",
	"sp":    "Policy for subdomains",
	"rua":   "Aggregate report destination",
	"ruf":   "Forensic report destination",
	"pct":   "Percentage of mail the policy applies to",
	"adkim": "DKIM alignment (r=relaxed, s=strict)",
	"aspf":  "SPF alignment (r=relaxed, s=strict)",
	"fo":    "Forensic reporting options",
	"rf":    "Forensic report format",
	"ri":    "Aggregate report interval (seconds)",
	"np":    "Policy for non-existent subdomains",
}

func parseTags(record string) ([]string, map[string]string) {
	var order []string
	tags := map[string]string{}
	for _, part := range strings.Split(record, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		k = strings.ToLower(strings.TrimSpace(k))
		order = append(order, k)
		tags[k] = strings.TrimSpace(v)
	}
	return order, tags
}

func cmdDMARC(ctx context.Context, res *Resolver, arg string, out *Result) error {
	domain, err := cleanDomain(arg)
	if err != nil {
		return err
	}
	domain = strings.TrimPrefix(domain, "_dmarc.")
	out.Query = domain
	name := "_dmarc." + domain
	txts, qr, err := res.LookupTXT(ctx, name)
	if err != nil {
		return err
	}
	if qr != nil {
		out.Response = qr.Msg.String()
	}
	var recs []string
	for _, t := range txts {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(t)), "V=DMARC1") {
			recs = append(recs, t)
		}
	}
	out.Headers = []string{"Tag", "Value", "Description"}
	switch len(recs) {
	case 0:
		out.check(StatusFail, "DMARC record", "No DMARC record found at %s", name)
		return nil
	case 1:
		out.check(StatusPass, "DMARC record", "DMARC record found: %s", recs[0])
	default:
		out.check(StatusFail, "Single DMARC record", "%d DMARC records found; receivers will ignore them all", len(recs))
	}

	order, tags := parseTags(recs[0])
	for _, k := range order {
		desc := dmarcDescriptions[k]
		if desc == "" {
			desc = "Unknown tag"
			out.check(StatusWarn, "Valid syntax", "Unknown DMARC tag %q", k)
		}
		out.Rows = append(out.Rows, []string{k, tags[k], desc})
	}

	switch strings.ToLower(tags["p"]) {
	case "reject":
		out.check(StatusPass, "DMARC policy", "Policy is reject")
	case "quarantine":
		out.check(StatusPass, "DMARC policy", "Policy is quarantine")
	case "none":
		out.check(StatusWarn, "DMARC policy", "Policy is none (monitoring only); spoofed mail is not blocked")
	case "":
		out.check(StatusFail, "DMARC policy", "Required p= tag is missing")
	default:
		out.check(StatusFail, "DMARC policy", "Invalid policy %q", tags["p"])
	}
	if order[0] != "v" {
		out.check(StatusFail, "Valid syntax", "v=DMARC1 must be the first tag")
	}
	if pct, ok := tags["pct"]; ok {
		if n, err := strconv.Atoi(pct); err != nil || n < 0 || n > 100 {
			out.check(StatusFail, "DMARC pct", "Invalid pct value %q", pct)
		} else if n < 100 {
			out.check(StatusWarn, "DMARC pct", "Policy only applies to %d%% of mail", n)
		}
	}
	if tags["rua"] == "" {
		out.check(StatusInfo, "Aggregate reports", "No rua= tag; you won't receive aggregate reports")
	} else {
		out.check(StatusPass, "Aggregate reports", "Aggregate reports sent to %s", tags["rua"])
	}
	return nil
}

// ---------------------------------------------------------------- DKIM

var dkimDescriptions = map[string]string{
	"v": "Version",
	"k": "Key type",
	"p": "Public key",
	"h": "Acceptable hash algorithms",
	"s": "Service type",
	"t": "Flags (y=testing, s=strict)",
	"n": "Notes",
}

func cmdDKIM(ctx context.Context, res *Resolver, arg string, out *Result) error {
	selector, domainArg, ok := strings.Cut(arg, ":")
	if !ok || selector == "" {
		return fmt.Errorf("usage: dkim:selector:domain (e.g. dkim:google:example.com)")
	}
	domain, err := cleanDomain(domainArg)
	if err != nil {
		return err
	}
	name := strings.TrimSpace(selector) + "._domainkey." + domain
	if _, ok := dns.IsDomainName(name); !ok {
		return fmt.Errorf("invalid selector %q", selector)
	}
	out.Query = name
	txts, qr, err := res.LookupTXT(ctx, name)
	if err != nil {
		return err
	}
	if qr != nil {
		out.Response = qr.Msg.String()
	}
	out.Headers = []string{"Tag", "Value", "Description"}
	if len(txts) == 0 {
		out.check(StatusFail, "DKIM record", "No DKIM record found at %s", name)
		return nil
	}
	rec := txts[0]
	out.check(StatusPass, "DKIM record", "DKIM record found")
	order, tags := parseTags(rec)
	for _, k := range order {
		desc := dkimDescriptions[k]
		if desc == "" {
			desc = "Unknown tag"
		}
		out.Rows = append(out.Rows, []string{k, tags[k], desc})
	}
	if v, ok := tags["v"]; ok && v != "DKIM1" {
		out.check(StatusFail, "DKIM version", "v= must be DKIM1, got %q", v)
	}
	p := strings.Join(strings.Fields(tags["p"]), "")
	if p == "" {
		out.check(StatusWarn, "Public key", "Empty p= tag: this key has been revoked")
		return nil
	}
	der, err := base64.StdEncoding.DecodeString(p)
	if err != nil {
		out.check(StatusFail, "Public key", "p= is not valid base64: %v", err)
		return nil
	}
	if strings.EqualFold(tags["k"], "ed25519") {
		if len(der) == ed25519.PublicKeySize {
			out.check(StatusPass, "Public key", "Valid Ed25519 public key")
		} else {
			out.check(StatusFail, "Public key", "Ed25519 key must be 32 bytes, got %d", len(der))
		}
		return nil
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		// Some publishers use a bare PKCS#1 RSA key.
		if rk, err2 := x509.ParsePKCS1PublicKey(der); err2 == nil {
			pub = rk
		} else {
			out.check(StatusFail, "Public key", "Could not parse public key: %v", err)
			return nil
		}
	}
	switch k := pub.(type) {
	case *rsa.PublicKey:
		bits := k.N.BitLen()
		switch {
		case bits < 1024:
			out.check(StatusFail, "Key length", "RSA key is %d bits; minimum is 1024", bits)
		case bits < 2048:
			out.check(StatusWarn, "Key length", "RSA key is %d bits; 2048 is recommended", bits)
		default:
			out.check(StatusPass, "Key length", "RSA key is %d bits", bits)
		}
	case *ecdsa.PublicKey:
		out.check(StatusInfo, "Key type", "ECDSA key (%s)", k.Curve.Params().Name)
	default:
		out.check(StatusInfo, "Key type", "Key type %T", k)
	}
	if strings.Contains(tags["t"], "y") {
		out.check(StatusInfo, "Testing mode", "t=y: domain is testing DKIM; verifiers may ignore failures")
	}
	return nil
}

// ---------------------------------------------------------------- Blacklists

// dnsbls is the list of IP-based DNS blocklists checked by the blacklist command.
var dnsbls = []string{
	"zen.spamhaus.org",
	"bl.spamcop.net",
	"b.barracudacentral.org",
	"psbl.surriel.com",
	"dnsbl-1.uceprotect.net",
	"dnsbl-2.uceprotect.net",
	"bl.mailspike.net",
	"truncate.gbudb.net",
	"dnsbl.dronebl.org",
	"all.s5h.net",
	"spam.dnsbl.anonmails.de",
	"bl.0spam.org",
	"bl.blocklist.de",
	"rbl.interserver.net",
}

type blResult struct {
	list, status, detail string
}

func checkDNSBL(ctx context.Context, res *Resolver, ip net.IP, list string) blResult {
	r := blResult{list: list}
	v4 := ip.To4()
	if v4 == nil {
		r.status, r.detail = "Skipped", "IPv6 not supported by this check"
		return r
	}
	name := fmt.Sprintf("%d.%d.%d.%d.%s", v4[3], v4[2], v4[1], v4[0], list)
	rrs, qr, err := res.Answers(ctx, name, dns.TypeA)
	if err != nil {
		r.status, r.detail = "Error", err.Error()
		return r
	}
	if qr.Msg.Rcode == dns.RcodeNameError || len(rrs) == 0 {
		r.status = "OK"
		return r
	}
	code := rrs[0].(*dns.A).A.String()
	// 127.255.255.x is the convention for "query refused" (e.g. Spamhaus
	// blocks lookups via public resolvers).
	if strings.HasPrefix(code, "127.255.255.") || !strings.HasPrefix(code, "127.") {
		r.status, r.detail = "Error", "Query refused by list ("+code+"); try a different resolver"
		return r
	}
	r.status, r.detail = "LISTED", code
	if txts, _, err := res.LookupTXT(ctx, name); err == nil && len(txts) > 0 {
		r.detail = code + " " + txts[0]
	}
	return r
}

func cmdBlacklist(ctx context.Context, res *Resolver, arg string, out *Result) error {
	arg = strings.TrimSpace(arg)
	var ips []net.IP
	if ip := net.ParseIP(arg); ip != nil {
		ips = []net.IP{ip}
		out.Query = ip.String()
	} else {
		// For a domain, check its mail servers, or failing that its A records.
		domain, err := cleanDomain(arg)
		if err != nil {
			return err
		}
		out.Query = domain
		hosts := []string{domain}
		if mxs, _, err := res.Answers(ctx, domain, dns.TypeMX); err == nil && len(mxs) > 0 {
			hosts = nil
			for _, mx := range mxs {
				hosts = append(hosts, mx.(*dns.MX).Mx)
			}
		}
		seen := map[string]bool{}
		for _, h := range hosts {
			for _, s := range res.LookupIPs(ctx, h) {
				if ip := net.ParseIP(s); ip != nil && ip.To4() != nil && !seen[s] && len(ips) < 4 {
					seen[s] = true
					ips = append(ips, ip)
				}
			}
		}
		if len(ips) == 0 {
			return fmt.Errorf("could not resolve any IPv4 mail server addresses for %s", domain)
		}
	}

	out.Headers = []string{"IP Address", "Blacklist", "Status", "Details"}
	type job struct {
		ip   net.IP
		list string
	}
	var jobs []job
	for _, ip := range ips {
		for _, l := range dnsbls {
			jobs = append(jobs, job{ip, l})
		}
	}
	results := make([]blResult, len(jobs))
	sem := make(chan struct{}, 16)
	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Add(1)
		go func(i int, j job) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = checkDNSBL(ctx, res, j.ip, j.list)
		}(i, j)
	}
	wg.Wait()

	listed, errs := 0, 0
	for i, r := range results {
		out.Rows = append(out.Rows, []string{jobs[i].ip.String(), r.list, r.status, r.detail})
		switch r.status {
		case "LISTED":
			listed++
			out.check(StatusFail, "Listed", "%s is listed on %s", jobs[i].ip, r.list)
		case "Error":
			errs++
		}
	}
	if listed == 0 {
		out.check(StatusPass, "Blacklists", "Not listed on any of %d blacklists checked", len(dnsbls))
	}
	if errs > 0 {
		out.check(StatusWarn, "Lookup errors", "%d blacklist queries failed or were refused", errs)
	}
	return nil
}
