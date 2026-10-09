package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// rdapBootstrapURL is IANA's registry of RDAP servers per TLD (RFC 9224).
const rdapBootstrapURL = "https://data.iana.org/rdap/dns.json"

const rdapMaxBody = 2 << 20 // 2 MiB is far more than any domain object needs

var rdapClient = &http.Client{Timeout: 15 * time.Second}

// rdapBootstrap caches the TLD → RDAP base URL map for a day.
var rdapBootstrap struct {
	sync.Mutex
	servers map[string]string
	fetched time.Time
}

var errRDAPNotFound = errors.New("not found")

// rdapGet fetches url and decodes its JSON body into v, returning the raw body.
func rdapGet(ctx context.Context, url string, v any) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	resp, err := rdapClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, rdapMaxBody))
	if err != nil {
		return nil, err
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return body, errRDAPNotFound
	case resp.StatusCode != http.StatusOK:
		return body, fmt.Errorf("%s returned %s", url, resp.Status)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return body, fmt.Errorf("invalid RDAP response from %s: %w", url, err)
	}
	return body, nil
}

// rdapServerFor returns the RDAP base URL (ending in "/") for domain's TLD.
func rdapServerFor(ctx context.Context, domain string) (string, error) {
	rdapBootstrap.Lock()
	defer rdapBootstrap.Unlock()
	if rdapBootstrap.servers == nil || time.Since(rdapBootstrap.fetched) > 24*time.Hour {
		var boot struct {
			Services [][][]string `json:"services"`
		}
		if _, err := rdapGet(ctx, rdapBootstrapURL, &boot); err != nil {
			return "", fmt.Errorf("fetching RDAP bootstrap: %w", err)
		}
		servers := map[string]string{}
		for _, svc := range boot.Services {
			if len(svc) != 2 {
				continue
			}
			base := ""
			for _, u := range svc[1] {
				if strings.HasPrefix(u, "https://") {
					base = u
					break
				}
			}
			if base == "" {
				continue
			}
			if !strings.HasSuffix(base, "/") {
				base += "/"
			}
			for _, tld := range svc[0] {
				servers[strings.ToLower(tld)] = base
			}
		}
		rdapBootstrap.servers, rdapBootstrap.fetched = servers, time.Now()
	}
	tld := domain[strings.LastIndex(domain, ".")+1:]
	if s, ok := rdapBootstrap.servers[tld]; ok {
		return s, nil
	}
	return "", fmt.Errorf("no RDAP server is registered for .%s", tld)
}

type rdapEntity struct {
	Roles     []string `json:"roles"`
	VCard     []any    `json:"vcardArray"`
	PublicIDs []struct {
		Type       string `json:"type"`
		Identifier string `json:"identifier"`
	} `json:"publicIds"`
	Entities []rdapEntity `json:"entities"`
}

// name returns the vCard "fn" (full name) of the entity.
func (e rdapEntity) name() string {
	if fn := vcardValues(e, "fn"); len(fn) > 0 {
		return fn[0]
	}
	return ""
}

func (e rdapEntity) hasRole(role string) bool {
	for _, r := range e.Roles {
		if r == role {
			return true
		}
	}
	return false
}

type rdapDomain struct {
	LDHName string   `json:"ldhName"`
	Status  []string `json:"status"`
	Events  []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
	Entities    []rdapEntity `json:"entities"`
	Nameservers []struct {
		LDHName string `json:"ldhName"`
	} `json:"nameservers"`
	SecureDNS *struct {
		DelegationSigned bool `json:"delegationSigned"`
	} `json:"secureDNS"`
}

var rdapEventLabels = map[string]string{
	"registration":                 "Registered",
	"expiration":                   "Expires",
	"last changed":                 "Last changed",
	"transfer":                     "Transferred",
	"last update of RDAP database": "RDAP data updated",
	"reregistration":               "Re-registered",
	"deletion":                     "Deleted",
	"registrar expiration":         "Registrar expiry",
	"enum validation expiration":   "ENUM validation expiry",
	"reinstantiation":              "Reinstated",
	"locked":                       "Locked",
	"unlocked":                     "Unlocked",
}

// cmdRDAP looks up a domain's registration data. Subdomains are walked up
// one label at a time until the registry recognises the name.
func cmdRDAP(ctx context.Context, _ *Resolver, arg string, out *Result) error {
	domain, err := cleanDomain(arg)
	if err != nil {
		return err
	}
	out.Query = domain
	if !strings.Contains(domain, ".") {
		return fmt.Errorf("%q is a TLD; RDAP lookups need a registered domain", domain)
	}
	base, err := rdapServerFor(ctx, domain)
	if err != nil {
		return err
	}
	out.Server = base

	var d rdapDomain
	var raw []byte
	name := domain
	for {
		raw, err = rdapGet(ctx, base+"domain/"+name, &d)
		if !errors.Is(err, errRDAPNotFound) || strings.Count(name, ".") < 2 {
			break
		}
		name = name[strings.Index(name, ".")+1:]
	}
	if len(raw) > 0 {
		var buf bytes.Buffer
		if json.Indent(&buf, raw, "", "  ") == nil {
			out.Response = buf.String()
		} else {
			out.Response = string(raw)
		}
	}
	if errors.Is(err, errRDAPNotFound) {
		out.check(StatusFail, "Registered", "The registry has no record of %s", domain)
		return nil
	}
	if err != nil {
		return err
	}
	if name != domain {
		out.check(StatusInfo, "Registered domain", "%s is part of the registered domain %s", domain, name)
	}

	out.Headers = []string{"Field", "Value"}
	add := func(field, value string) {
		if value != "" {
			out.Rows = append(out.Rows, []string{field, value})
		}
	}
	add("Domain", strings.ToLower(strings.TrimSuffix(d.LDHName, ".")))

	var registrar string
	for _, e := range d.Entities {
		if !e.hasRole("registrar") {
			continue
		}
		registrar = e.name()
		add("Registrar", registrar)
		for _, id := range e.PublicIDs {
			if id.Type == "IANA Registrar ID" {
				add("IANA Registrar ID", id.Identifier)
			}
		}
		for _, sub := range e.Entities {
			if sub.hasRole("abuse") {
				add("Registrar abuse contact", strings.Join(vcardValues(sub, "email", "tel"), "\n"))
			}
		}
	}
	for _, e := range d.Entities {
		if e.hasRole("registrant") {
			add("Registrant", e.name())
		}
	}

	var expires time.Time
	for _, ev := range d.Events {
		label := rdapEventLabels[ev.Action]
		if label == "" {
			label = ev.Action
		}
		value := ev.Date
		if t, err := time.Parse(time.RFC3339, ev.Date); err == nil {
			value = t.UTC().Format("2006-01-02 15:04 MST")
			if ev.Action == "expiration" {
				expires = t
			}
		}
		add(label, value)
	}

	add("Status", strings.Join(d.Status, "\n"))
	ns := make([]string, 0, len(d.Nameservers))
	for _, n := range d.Nameservers {
		ns = append(ns, strings.ToLower(strings.TrimSuffix(n.LDHName, ".")))
	}
	sort.Strings(ns)
	add("Name servers", strings.Join(ns, "\n"))
	if d.SecureDNS != nil {
		add("DNSSEC", map[bool]string{true: "signed", false: "unsigned"}[d.SecureDNS.DelegationSigned])
	}

	out.check(StatusPass, "Registered", "%s is registered", name)
	if registrar == "" {
		out.check(StatusInfo, "Registrar", "The registry did not name a registrar")
	}
	switch days := time.Until(expires).Hours() / 24; {
	case expires.IsZero():
		out.check(StatusInfo, "Expiry", "The registry did not give an expiry date")
	case days < 0:
		out.check(StatusFail, "Expiry", "Registration expired on %s", expires.UTC().Format("2006-01-02"))
	case days < 30:
		out.check(StatusWarn, "Expiry", "Registration expires in %d day(s)", int(days))
	default:
		out.check(StatusPass, "Expiry", "Registration expires in %d days", int(days))
	}
	for _, s := range d.Status {
		switch s {
		case "client hold", "server hold":
			out.check(StatusFail, "Status", "Domain is on %s and will not resolve", s)
		case "pending delete", "redemption period":
			out.check(StatusWarn, "Status", "Domain is in %s", s)
		}
	}
	if len(ns) == 0 {
		out.check(StatusWarn, "Name servers", "No name servers are delegated")
	}
	return nil
}

// vcardValues returns the values of the given vCard properties, in order.
func vcardValues(e rdapEntity, props ...string) []string {
	if len(e.VCard) != 2 {
		return nil
	}
	fields, _ := e.VCard[1].([]any)
	var vals []string
	for _, want := range props {
		for _, p := range fields {
			f, _ := p.([]any)
			if len(f) == 4 && f[0] == want {
				if s, ok := f[3].(string); ok && s != "" {
					vals = append(vals, strings.TrimPrefix(s, "tel:"))
				}
			}
		}
	}
	return vals
}
