package main

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Status values for health checks.
const (
	StatusPass = "pass"
	StatusWarn = "warn"
	StatusFail = "fail"
	StatusInfo = "info"
)

// Check is a single pass/warn/fail test shown under the results table.
type Check struct {
	Status  string `json:"status"`
	Name    string `json:"name"`
	Message string `json:"message"`
}

// Result is the generic response for every command: a table plus checks.
type Result struct {
	Command  string     `json:"command"`
	Query    string     `json:"query"`
	Server   string     `json:"server"`
	TimeMS   int64      `json:"time_ms"`
	Headers  []string   `json:"headers"`
	Rows     [][]string `json:"rows"`
	Checks   []Check    `json:"checks"`
	Error    string     `json:"error,omitempty"`
	Response string     `json:"response,omitempty"` // dig-style raw output
}

func (r *Result) check(status, name, format string, args ...any) {
	r.Checks = append(r.Checks, Check{Status: status, Name: name, Message: fmt.Sprintf(format, args...)})
}

type handlerFunc func(ctx context.Context, res *Resolver, arg string, out *Result) error

type command struct {
	Name        string
	Description string
	Example     string
	Handler     handlerFunc
}

var commands []command
var commandIndex = map[string]*command{}

func init() {
	commands = []command{
		{"mx", "Mail exchanger records, with resolved IPs", "mx:example.com", cmdMX},
		{"a", "IPv4 address records", "a:example.com", recordCmd(dns.TypeA)},
		{"aaaa", "IPv6 address records", "aaaa:example.com", recordCmd(dns.TypeAAAA)},
		{"ns", "Name server records, with resolved IPs", "ns:example.com", cmdNS},
		{"txt", "Text records", "txt:example.com", recordCmd(dns.TypeTXT)},
		{"cname", "Canonical name records", "cname:www.example.com", recordCmd(dns.TypeCNAME)},
		{"soa", "Start of authority record", "soa:example.com", cmdSOA},
		{"ptr", "Reverse DNS lookup for an IP", "ptr:8.8.8.8", cmdPTR},
		{"srv", "Service records (_service._proto.name)", "srv:_sip._tcp.example.com", recordCmd(dns.TypeSRV)},
		{"caa", "Certificate authority authorization", "caa:example.com", recordCmd(dns.TypeCAA)},
		{"spf", "Parse and validate the SPF record", "spf:example.com", cmdSPF},
		{"dmarc", "Parse and validate the DMARC record", "dmarc:example.com", cmdDMARC},
		{"dkim", "DKIM public key (selector:domain)", "dkim:google:example.com", cmdDKIM},
		{"blacklist", "Check an IP (or a domain's mail servers) against DNSBLs", "blacklist:1.2.3.4", cmdBlacklist},
		{"dnssec", "DNSKEY / DS records and validation status", "dnssec:example.com", cmdDNSSEC},
		{"dns", "All common record types at once", "dns:example.com", cmdAll},
		{"rdap", "Domain registration data (registrar, dates, status) via RDAP", "rdap:example.com", cmdRDAP},
	}
	for i := range commands {
		commandIndex[commands[i].Name] = &commands[i]
	}
}

// parseQuery splits "mx:example.com" into ("mx", "example.com"). Bare input
// defaults to ptr for IPs and a (which also shows any CNAME chain) for names.
func parseQuery(q string) (string, string) {
	q = strings.TrimSpace(q)
	if i := strings.Index(q, ":"); i > 0 {
		if _, ok := commandIndex[strings.ToLower(q[:i])]; ok {
			return strings.ToLower(q[:i]), strings.TrimSpace(q[i+1:])
		}
	}
	if net.ParseIP(q) != nil {
		return "ptr", q
	}
	return "a", q
}

// cleanDomain strips URL noise and validates a domain name.
func cleanDomain(s string) (string, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "https://")
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return "", fmt.Errorf("no domain given")
	}
	if _, ok := dns.IsDomainName(s); !ok || len(s) > 253 {
		return "", fmt.Errorf("%q is not a valid domain name", s)
	}
	return s, nil
}

// Run executes a query string against the resolver.
func Run(ctx context.Context, res *Resolver, q string) *Result {
	name, arg := parseQuery(q)
	out := &Result{Command: name, Query: arg, Server: res.Server}
	start := time.Now()
	err := commandIndex[name].Handler(ctx, res, arg, out)
	out.TimeMS = time.Since(start).Milliseconds()
	if err != nil {
		out.Error = err.Error()
	}
	if out.Rows == nil {
		out.Rows = [][]string{}
	}
	if out.Checks == nil {
		out.Checks = []Check{}
	}
	return out
}

func ttl(rr dns.RR) string {
	return formatTTL(rr.Header().Ttl)
}

func formatTTL(s uint32) string {
	d := time.Duration(s) * time.Second
	switch {
	case s == 0:
		return "0s"
	case s%86400 == 0:
		return fmt.Sprintf("%dd", s/86400)
	case s%3600 == 0:
		return fmt.Sprintf("%dh", s/3600)
	case s >= 60 && s%60 == 0:
		return fmt.Sprintf("%dm", s/60)
	default:
		return d.String()
	}
}

// rdata returns the record data portion of rr (everything after the header).
func rdata(rr dns.RR) string {
	full := rr.String()
	hdr := rr.Header().String()
	return strings.TrimSpace(strings.TrimPrefix(full, hdr))
}

func rcodeCheck(out *Result, qr *QueryResult, what string) bool {
	if qr == nil {
		return false
	}
	out.Response = qr.Msg.String()
	if qr.Msg.Rcode == dns.RcodeNameError {
		out.check(StatusFail, "Domain exists", "%s does not exist (NXDOMAIN)", what)
		return false
	}
	return true
}

// recordCmd builds a simple handler that lists records of one type.
func recordCmd(qtype uint16) handlerFunc {
	return func(ctx context.Context, res *Resolver, arg string, out *Result) error {
		domain, err := cleanDomain(arg)
		if err != nil {
			return err
		}
		out.Query = domain
		rrs, qr, err := res.Answers(ctx, domain, qtype)
		if err != nil {
			return err
		}
		if !rcodeCheck(out, qr, domain) {
			return nil
		}
		// Show any CNAME chain that led to the answer.
		out.Headers = []string{"Type", "Name", "Value", "TTL"}
		for _, rr := range qr.Msg.Answer {
			t := rr.Header().Rrtype
			if t != qtype && t != dns.TypeCNAME {
				continue
			}
			val := rdata(rr)
			if txt, ok := rr.(*dns.TXT); ok {
				val = strings.Join(txt.Txt, "")
			}
			out.Rows = append(out.Rows, []string{dns.TypeToString[t], strings.TrimSuffix(rr.Header().Name, "."), val, ttl(rr)})
		}
		typ := dns.TypeToString[qtype]
		if len(rrs) == 0 {
			out.check(StatusWarn, typ+" records", "No %s records found for %s", typ, domain)
		} else {
			out.check(StatusPass, typ+" records", "Found %d %s record(s)", len(rrs), typ)
		}
		return nil
	}
}

func cmdMX(ctx context.Context, res *Resolver, arg string, out *Result) error {
	domain, err := cleanDomain(arg)
	if err != nil {
		return err
	}
	out.Query = domain
	rrs, qr, err := res.Answers(ctx, domain, dns.TypeMX)
	if err != nil {
		return err
	}
	if !rcodeCheck(out, qr, domain) {
		return nil
	}
	out.Headers = []string{"Pref", "Hostname", "IP Address", "TTL"}
	sort.Slice(rrs, func(i, j int) bool { return rrs[i].(*dns.MX).Preference < rrs[j].(*dns.MX).Preference })

	if len(rrs) == 0 {
		out.check(StatusFail, "MX records", "No MX records found for %s", domain)
		return nil
	}
	out.check(StatusPass, "MX records", "Found %d MX record(s)", len(rrs))

	rows := make([][]string, len(rrs))
	ipsFor := make([][]string, len(rrs))
	var wg sync.WaitGroup
	for i, rr := range rrs {
		wg.Add(1)
		go func(i int, mx *dns.MX) {
			defer wg.Done()
			host := strings.TrimSuffix(mx.Mx, ".")
			ips := res.LookupIPs(ctx, host)
			ipsFor[i] = ips
			rows[i] = []string{fmt.Sprint(mx.Preference), host, strings.Join(ips, "\n"), ttl(mx)}
		}(i, rr.(*dns.MX))
	}
	wg.Wait()
	out.Rows = rows

	if len(rrs) == 1 && rrs[0].(*dns.MX).Mx == "." {
		out.check(StatusInfo, "Null MX", "Domain explicitly accepts no mail (RFC 7505 null MX)")
		return nil
	}
	if len(rrs) == 1 {
		out.check(StatusInfo, "MX redundancy", "Only one MX record; consider a backup mail server")
	}
	for i, rr := range rrs {
		host := rr.(*dns.MX).Mx
		if net.ParseIP(strings.TrimSuffix(host, ".")) != nil {
			out.check(StatusFail, "MX is hostname", "%s is an IP address; MX records must point to a hostname", host)
		} else if len(ipsFor[i]) == 0 {
			out.check(StatusFail, "MX resolves", "%s has no A/AAAA records", strings.TrimSuffix(host, "."))
		}
		if cn, _, _ := res.Answers(ctx, host, dns.TypeCNAME); len(cn) > 0 {
			out.check(StatusWarn, "MX not CNAME", "%s is a CNAME; MX targets should not be aliases (RFC 2181)", strings.TrimSuffix(host, "."))
		}
	}
	return nil
}

func cmdNS(ctx context.Context, res *Resolver, arg string, out *Result) error {
	domain, err := cleanDomain(arg)
	if err != nil {
		return err
	}
	out.Query = domain
	rrs, qr, err := res.Answers(ctx, domain, dns.TypeNS)
	if err != nil {
		return err
	}
	if !rcodeCheck(out, qr, domain) {
		return nil
	}
	out.Headers = []string{"Name Server", "IP Address", "SOA Serial", "TTL"}
	if len(rrs) == 0 {
		out.check(StatusFail, "NS records", "No NS records found for %s (is it a zone apex?)", domain)
		return nil
	}
	out.check(StatusPass, "NS records", "Found %d name server(s)", len(rrs))
	if len(rrs) < 2 {
		out.check(StatusWarn, "NS redundancy", "RFC 1034 recommends at least two name servers")
	}

	rows := make([][]string, len(rrs))
	serials := make([]string, len(rrs))
	var wg sync.WaitGroup
	for i, rr := range rrs {
		wg.Add(1)
		go func(i int, ns *dns.NS) {
			defer wg.Done()
			host := strings.TrimSuffix(ns.Ns, ".")
			ips := res.LookupIPs(ctx, host)
			serial := "-"
			if len(ips) > 0 {
				// Ask the name server directly for its SOA serial.
				auth := &Resolver{Server: net.JoinHostPort(ips[0], "53"), Timeout: res.Timeout}
				if soa, _, err := auth.Answers(ctx, domain, dns.TypeSOA); err == nil && len(soa) > 0 {
					serial = fmt.Sprint(soa[0].(*dns.SOA).Serial)
				} else {
					serial = "no answer"
				}
			}
			serials[i] = serial
			rows[i] = []string{host, strings.Join(ips, "\n"), serial, ttl(ns)}
		}(i, rr.(*dns.NS))
	}
	wg.Wait()
	sort.Slice(rows, func(i, j int) bool { return rows[i][0] < rows[j][0] })
	out.Rows = rows

	uniq := map[string]bool{}
	for _, s := range serials {
		if s != "-" && s != "no answer" {
			uniq[s] = true
		}
	}
	switch {
	case len(uniq) == 1:
		out.check(StatusPass, "SOA serials agree", "All responding name servers report the same SOA serial")
	case len(uniq) > 1:
		out.check(StatusWarn, "SOA serials agree", "Name servers report different SOA serials; zone may not be in sync")
	}
	for _, s := range serials {
		if s == "no answer" {
			out.check(StatusWarn, "NS responds", "One or more name servers did not answer authoritatively")
			break
		}
	}
	return nil
}

func cmdSOA(ctx context.Context, res *Resolver, arg string, out *Result) error {
	domain, err := cleanDomain(arg)
	if err != nil {
		return err
	}
	out.Query = domain
	rrs, qr, err := res.Answers(ctx, domain, dns.TypeSOA)
	if err != nil {
		return err
	}
	if !rcodeCheck(out, qr, domain) {
		return nil
	}
	out.Headers = []string{"Field", "Value", "Description"}
	if len(rrs) == 0 {
		out.check(StatusWarn, "SOA record", "No SOA record at %s (not a zone apex?)", domain)
		return nil
	}
	soa := rrs[0].(*dns.SOA)
	out.Rows = [][]string{
		{"Primary NS", strings.TrimSuffix(soa.Ns, "."), "Primary master name server"},
		{"Responsible", strings.TrimSuffix(soa.Mbox, "."), "Administrator mailbox (first . is @)"},
		{"Serial", fmt.Sprint(soa.Serial), "Zone version number"},
		{"Refresh", formatTTL(soa.Refresh), "How often secondaries check for updates"},
		{"Retry", formatTTL(soa.Retry), "Retry interval after a failed refresh"},
		{"Expire", formatTTL(soa.Expire), "When secondaries stop answering without a refresh"},
		{"Minimum TTL", formatTTL(soa.Minttl), "Negative caching TTL"},
		{"TTL", ttl(soa), "TTL of the SOA record itself"},
	}
	out.check(StatusPass, "SOA record", "SOA record found")
	if soa.Refresh < 1200 || soa.Refresh > 43200 {
		out.check(StatusWarn, "SOA refresh", "Refresh %s is outside the recommended 20m–12h range (RFC 1912)", formatTTL(soa.Refresh))
	}
	if soa.Retry >= soa.Refresh {
		out.check(StatusWarn, "SOA retry", "Retry should be lower than refresh")
	}
	if soa.Expire < 604800 || soa.Expire > 2419200 {
		out.check(StatusWarn, "SOA expire", "Expire %s is outside the recommended 1–4 week range", formatTTL(soa.Expire))
	}
	if soa.Minttl > 86400 {
		out.check(StatusWarn, "SOA minimum", "Negative caching TTL over 1 day may delay new records (RFC 2308)")
	}
	return nil
}

func cmdPTR(ctx context.Context, res *Resolver, arg string, out *Result) error {
	ip := net.ParseIP(strings.TrimSpace(arg))
	if ip == nil {
		return fmt.Errorf("%q is not a valid IP address", arg)
	}
	out.Query = ip.String()
	rev, err := dns.ReverseAddr(ip.String())
	if err != nil {
		return err
	}
	rrs, qr, err := res.Answers(ctx, rev, dns.TypePTR)
	if err != nil {
		return err
	}
	out.Response = qr.Msg.String()
	out.Headers = []string{"IP Address", "Hostname", "Forward Confirmed", "TTL"}
	if len(rrs) == 0 {
		out.check(StatusFail, "PTR record", "No reverse DNS (PTR) record for %s", ip)
		return nil
	}
	out.check(StatusPass, "PTR record", "Found %d PTR record(s)", len(rrs))
	for _, rr := range rrs {
		host := strings.TrimSuffix(rr.(*dns.PTR).Ptr, ".")
		confirmed := "No"
		for _, fip := range res.LookupIPs(ctx, host) {
			if net.ParseIP(fip).Equal(ip) {
				confirmed = "Yes"
			}
		}
		if confirmed == "Yes" {
			out.check(StatusPass, "Forward-confirmed rDNS", "%s resolves back to %s", host, ip)
		} else {
			out.check(StatusWarn, "Forward-confirmed rDNS", "%s does not resolve back to %s", host, ip)
		}
		out.Rows = append(out.Rows, []string{ip.String(), host, confirmed, ttl(rr)})
	}
	return nil
}

func cmdDNSSEC(ctx context.Context, res *Resolver, arg string, out *Result) error {
	domain, err := cleanDomain(arg)
	if err != nil {
		return err
	}
	out.Query = domain
	out.Headers = []string{"Type", "Key Tag", "Algorithm", "Details", "TTL"}

	keys, kqr, err := res.Answers(ctx, domain, dns.TypeDNSKEY)
	if err != nil {
		return err
	}
	if !rcodeCheck(out, kqr, domain) {
		return nil
	}
	ds, _, err := res.Answers(ctx, domain, dns.TypeDS)
	if err != nil {
		return err
	}
	for _, rr := range keys {
		k := rr.(*dns.DNSKEY)
		role := "ZSK"
		if k.Flags&dns.SEP != 0 {
			role = "KSK"
		}
		out.Rows = append(out.Rows, []string{"DNSKEY", fmt.Sprint(k.KeyTag()), dns.AlgorithmToString[k.Algorithm],
			fmt.Sprintf("%s, flags %d", role, k.Flags), ttl(k)})
	}
	for _, rr := range ds {
		d := rr.(*dns.DS)
		out.Rows = append(out.Rows, []string{"DS", fmt.Sprint(d.KeyTag), dns.AlgorithmToString[d.Algorithm],
			fmt.Sprintf("digest %s: %s", dns.HashToString[d.DigestType], strings.ToLower(d.Digest)), ttl(d)})
	}

	switch {
	case len(keys) == 0 && len(ds) == 0:
		out.check(StatusWarn, "DNSSEC", "DNSSEC is not enabled for %s", domain)
		return nil
	case len(keys) == 0:
		out.check(StatusFail, "DNSKEY", "DS record exists at parent but no DNSKEY found; zone will fail validation")
	case len(ds) == 0:
		out.check(StatusWarn, "DS record", "DNSKEY published but no DS at parent; chain of trust is broken")
	default:
		out.check(StatusPass, "DNSKEY & DS", "DNSKEY and DS records are present")
		matched := false
		for _, d := range ds {
			for _, k := range keys {
				if d.(*dns.DS).KeyTag == k.(*dns.DNSKEY).KeyTag() {
					matched = true
				}
			}
		}
		if matched {
			out.check(StatusPass, "DS matches DNSKEY", "At least one DS key tag matches a published DNSKEY")
		} else {
			out.check(StatusFail, "DS matches DNSKEY", "No DS record matches any published DNSKEY")
		}
	}
	if kqr.Msg.AuthenticatedData {
		out.check(StatusPass, "Validated", "Resolver validated the response (AD flag set)")
	} else {
		out.check(StatusInfo, "Validated", "Resolver did not set the AD flag (it may not validate DNSSEC)")
	}
	return nil
}

// cmdAll queries the common record types in parallel.
func cmdAll(ctx context.Context, res *Resolver, arg string, out *Result) error {
	domain, err := cleanDomain(arg)
	if err != nil {
		return err
	}
	out.Query = domain
	out.Headers = []string{"Type", "Name", "Value", "TTL"}
	types := []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeMX, dns.TypeTXT, dns.TypeCAA}
	results := make([][]dns.RR, len(types))
	errs := make([]error, len(types))
	var nx bool
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i, t := range types {
		wg.Add(1)
		go func(i int, t uint16) {
			defer wg.Done()
			rrs, qr, err := res.Answers(ctx, domain, t)
			results[i], errs[i] = rrs, err
			if qr != nil && qr.Msg.Rcode == dns.RcodeNameError {
				mu.Lock()
				nx = true
				mu.Unlock()
			}
		}(i, t)
	}
	wg.Wait()
	if nx {
		out.check(StatusFail, "Domain exists", "%s does not exist (NXDOMAIN)", domain)
		return nil
	}
	for i, t := range types {
		if errs[i] != nil {
			out.check(StatusWarn, dns.TypeToString[t], "%v", errs[i])
			continue
		}
		for _, rr := range results[i] {
			val := rdata(rr)
			if txt, ok := rr.(*dns.TXT); ok {
				val = strings.Join(txt.Txt, "")
			}
			out.Rows = append(out.Rows, []string{dns.TypeToString[t], strings.TrimSuffix(rr.Header().Name, "."), val, ttl(rr)})
		}
	}
	out.check(StatusInfo, "Records", "Found %d record(s) across %d types", len(out.Rows), len(types))
	return nil
}
