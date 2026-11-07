package main

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// maxTraceHops bounds the number of referrals followed from the root.
const maxTraceHops = 16

// Trace resolves name/qtype iteratively from the root servers, like
// "dig +trace", and returns dig-style output for every step. The configured
// resolver is used to find the root servers and the addresses of name
// servers that came without glue.
func (r *Resolver) Trace(ctx context.Context, name string, qtype uint16) string {
	var b strings.Builder
	name = dns.Fqdn(name)
	fmt.Fprintf(&b, "; <<>> dnsdash trace <<>> %s %s\n", name, dns.TypeToString[qtype])

	roots, err := r.Query(ctx, ".", dns.TypeNS)
	if err != nil {
		fmt.Fprintf(&b, ";; %v\n", err)
		return b.String()
	}
	writeTraceStep(&b, roots.Msg, r.Server, "", roots.RTT.Milliseconds())

	servers := nsNames(roots.Msg.Answer)
	glue := glueAddrs(roots.Msg.Extra)
	for range maxTraceHops {
		if len(servers) == 0 {
			b.WriteString(";; no name servers to follow\n")
			return b.String()
		}
		resp, host, addr, rtt, err := r.queryAny(ctx, servers, glue, name, qtype)
		if err != nil {
			fmt.Fprintf(&b, ";; %v\n", err)
			return b.String()
		}
		writeTraceStep(&b, resp, addr, host, rtt)

		next := nsNames(resp.Ns)
		// Stop on an answer, an error, an authoritative reply, or a referral
		// that does not move closer to the name.
		if len(resp.Answer) > 0 || resp.Rcode != dns.RcodeSuccess || resp.Authoritative || len(next) == 0 ||
			!dns.IsSubDomain(resp.Ns[0].Header().Name, name) || sameZone(resp.Ns[0].Header().Name, servers) {
			return b.String()
		}
		servers, glue = next, glueAddrs(resp.Extra)
		servers = withZone(servers, resp.Ns[0].Header().Name)
	}
	b.WriteString(";; too many referrals\n")
	return b.String()
}

// traceServer is a name server together with the zone it was delegated for.
type traceServer struct {
	host, zone string
}

func nsNames(rrs []dns.RR) []traceServer {
	var out []traceServer
	for _, rr := range rrs {
		if ns, ok := rr.(*dns.NS); ok {
			out = append(out, traceServer{host: ns.Ns, zone: ns.Header().Name})
		}
	}
	return out
}

func withZone(s []traceServer, zone string) []traceServer {
	for i := range s {
		s[i].zone = zone
	}
	return s
}

func sameZone(zone string, prev []traceServer) bool {
	return len(prev) > 0 && strings.EqualFold(prev[0].zone, zone) && zone != "."
}

// glueAddrs maps name server names to IPv4 glue addresses, falling back to
// IPv6 only when a server has no IPv4 glue.
func glueAddrs(rrs []dns.RR) map[string][]string {
	v4, v6 := map[string][]string{}, map[string][]string{}
	for _, rr := range rrs {
		n := strings.ToLower(rr.Header().Name)
		switch v := rr.(type) {
		case *dns.A:
			v4[n] = append(v4[n], v.A.String())
		case *dns.AAAA:
			v6[n] = append(v6[n], v.AAAA.String())
		}
	}
	for n, ips := range v6 {
		if len(v4[n]) == 0 {
			v4[n] = ips
		}
	}
	return v4
}

// queryAny sends a non-recursive query to the given servers in turn until
// one answers, trying at most three.
func (r *Resolver) queryAny(ctx context.Context, servers []traceServer, glue map[string][]string,
	name string, qtype uint16) (*dns.Msg, string, string, int64, error) {
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.RecursionDesired = false
	m.SetEdns0(4096, true)

	var lastErr error
	tried := 0
	for _, s := range servers {
		if tried == 3 {
			break
		}
		ips := glue[strings.ToLower(s.host)]
		if len(ips) == 0 {
			// No glue: ask the configured resolver, preferring IPv4.
			for _, ip := range r.LookupIPs(ctx, strings.TrimSuffix(s.host, ".")) {
				if net.ParseIP(ip).To4() != nil {
					ips = []string{ip}
					break
				}
				if ips == nil {
					ips = []string{ip}
				}
			}
		}
		if len(ips) == 0 {
			continue
		}
		tried++
		addr := net.JoinHostPort(ips[0], "53")
		c := &dns.Client{Net: "udp", Timeout: r.Timeout}
		resp, rtt, err := c.ExchangeContext(ctx, m, addr)
		if err == nil && resp.Truncated {
			c.Net = "tcp"
			resp, rtt, err = c.ExchangeContext(ctx, m, addr)
		}
		if err != nil {
			lastErr = err
			continue
		}
		return resp, s.host, addr, rtt.Milliseconds(), nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("could not find an address for any name server")
	}
	return nil, "", "", 0, fmt.Errorf("query %s %s: %w", dns.TypeToString[qtype], name, lastErr)
}

// writeTraceStep prints one response's records in dig +trace style.
func writeTraceStep(b *strings.Builder, m *dns.Msg, addr, host string, rttMS int64) {
	b.WriteString("\n")
	if m.Rcode != dns.RcodeSuccess {
		fmt.Fprintf(b, ";; status: %s\n", dns.RcodeToString[m.Rcode])
	}
	for _, sec := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range sec {
			if rr.Header().Rrtype == dns.TypeOPT {
				continue
			}
			b.WriteString(rr.String())
			b.WriteString("\n")
		}
	}
	from := addr
	if host != "" {
		from = fmt.Sprintf("%s(%s)", addr, strings.TrimSuffix(host, "."))
	}
	fmt.Fprintf(b, ";; Received %d bytes from %s in %d ms\n", m.Len(), from, rttMS)
}
