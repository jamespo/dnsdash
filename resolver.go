package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Resolver sends DNS queries to a single upstream server.
type Resolver struct {
	Server  string // host:port
	Timeout time.Duration
}

// QueryResult is a raw DNS response plus timing information.
type QueryResult struct {
	Msg *dns.Msg
	RTT time.Duration
}

// Query sends a recursive query for name/qtype, retrying over TCP when the
// UDP answer is truncated.
func (r *Resolver) Query(ctx context.Context, name string, qtype uint16) (*QueryResult, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	m.SetEdns0(4096, true) // DO bit so we get AD / RRSIG information

	c := &dns.Client{Net: "udp", Timeout: r.Timeout}
	resp, rtt, err := c.ExchangeContext(ctx, m, r.Server)
	if err == nil && resp.Truncated {
		c.Net = "tcp"
		resp, rtt, err = c.ExchangeContext(ctx, m, r.Server)
	}
	if err != nil {
		return nil, fmt.Errorf("query %s %s via %s: %w", dns.TypeToString[qtype], name, r.Server, err)
	}
	return &QueryResult{Msg: resp, RTT: rtt}, nil
}

// Answers returns only the records in the answer section matching qtype.
func (r *Resolver) Answers(ctx context.Context, name string, qtype uint16) ([]dns.RR, *QueryResult, error) {
	res, err := r.Query(ctx, name, qtype)
	if err != nil {
		return nil, nil, err
	}
	if res.Msg.Rcode != dns.RcodeSuccess && res.Msg.Rcode != dns.RcodeNameError {
		return nil, res, fmt.Errorf("%s %s: server returned %s", dns.TypeToString[qtype], name, dns.RcodeToString[res.Msg.Rcode])
	}
	var out []dns.RR
	for _, rr := range res.Msg.Answer {
		if rr.Header().Rrtype == qtype {
			out = append(out, rr)
		}
	}
	return out, res, nil
}

// LookupIPs resolves A and AAAA records for host.
func (r *Resolver) LookupIPs(ctx context.Context, host string) []string {
	var ips []string
	for _, t := range []uint16{dns.TypeA, dns.TypeAAAA} {
		rrs, _, err := r.Answers(ctx, host, t)
		if err != nil {
			continue
		}
		for _, rr := range rrs {
			switch v := rr.(type) {
			case *dns.A:
				ips = append(ips, v.A.String())
			case *dns.AAAA:
				ips = append(ips, v.AAAA.String())
			}
		}
	}
	return ips
}

// LookupTXT returns the joined TXT strings for name.
func (r *Resolver) LookupTXT(ctx context.Context, name string) ([]string, *QueryResult, error) {
	rrs, res, err := r.Answers(ctx, name, dns.TypeTXT)
	if err != nil {
		return nil, res, err
	}
	var out []string
	for _, rr := range rrs {
		out = append(out, strings.Join(rr.(*dns.TXT).Txt, ""))
	}
	return out, res, nil
}

// normalizeServer turns "1.1.1.1" or "[2606:4700::1111]:53" into host:port.
func normalizeServer(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("empty resolver")
	}
	if ip := net.ParseIP(s); ip != nil {
		return net.JoinHostPort(ip.String(), "53"), nil
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", fmt.Errorf("invalid resolver %q: must be an IP address or ip:port", s)
	}
	if net.ParseIP(host) == nil {
		return "", fmt.Errorf("invalid resolver %q: must be an IP address", s)
	}
	return net.JoinHostPort(host, port), nil
}

// systemResolver returns the first nameserver from /etc/resolv.conf, or
// fallback if it cannot be read.
func systemResolver(fallback string) string {
	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil || len(cfg.Servers) == 0 {
		return fallback
	}
	return net.JoinHostPort(cfg.Servers[0], cfg.Port)
}
