# DNS Dash

A self-hosted web tool for DNS lookups, mail checks and RDAP domain registration lookups, modelled on
[MxToolbox SuperTool](https://mxtoolbox.com/SuperTool.aspx). It is a single
Go binary with the web page built in.

## Quick start

```sh
go build -o dnsdash .
./dnsdash
```

Then open <http://localhost:8080>.

Requires Go 1.25 or later (the minimum set by the `golang.org/x` dependencies).

## Command-line options

| Flag | Default | Description |
|---|---|---|
| `-addr` | `:8080` | Address to listen on |
| `-resolver` | first nameserver in `/etc/resolv.conf` (falls back to `1.1.1.1`) | Default DNS resolver, as `ip` or `ip:port` |
| `-allow-custom-resolver` | `true` | Let users choose their own resolver in the page or API |
| `-timeout` | `5s` | Timeout for each individual DNS query |

Examples:

```sh
./dnsdash -addr 127.0.0.1:9000
./dnsdash -resolver 9.9.9.9 -allow-custom-resolver=false
./dnsdash -resolver '[2606:4700:4700::1111]:53'
```

## Using the web page

Type a lookup in the search box as `command:target` and press **Lookup**, or
click a command button to fill the command in.

- A bare domain (`example.com`) runs an A lookup, which also shows any CNAME chain.
- A bare IP address (`8.8.8.8`) runs a reverse (PTR) lookup.
- URLs are accepted and cleaned, so `https://example.com/path` becomes `example.com`.

Each lookup appears as a card at the top of the page, showing:

- **A results table.** IPs and hostnames are links: clicking an IP runs a
  reverse lookup and clicking a hostname runs an A lookup.
- **Test results**, marked `PASS`, `WARN`, `FAIL` or `INFO`, with failures listed first.
- **Raw response**, a dig-style dump of the DNS answer, or the RDAP JSON for
  `rdap` lookups (click to expand).
- **Related lookups**, such as SPF, DMARC and blacklist after an MX lookup.

Use the dropdown to choose a resolver: the server default, Cloudflare, Google,
Quad9, or **Custom…** for any `ip` or `ip:port`.

The address bar always holds the current lookup (for example
`?q=spf:example.com&server=8.8.8.8`), so you can bookmark or share it.

## Commands

| Command | Example | What it does |
|---|---|---|
| `mx` | `mx:example.com` | MX records sorted by preference, with each host's IPs. Flags a missing MX, an MX that is an IP or a CNAME, an MX host that doesn't resolve, a single MX, and a null MX. |
| `a` | `a:example.com` | IPv4 address records (shows any CNAME chain) |
| `aaaa` | `aaaa:example.com` | IPv6 address records |
| `ns` | `ns:example.com` | Name servers with their IPs. Asks each one directly for its SOA serial and checks that they all match. |
| `txt` | `txt:example.com` | TXT records; long records split into several strings are joined back together |
| `cname` | `cname:www.example.com` | Canonical name (alias) records |
| `soa` | `soa:example.com` | Each SOA field explained, with timers checked against RFC 1912 and RFC 2308 recommendations |
| `ptr` | `ptr:8.8.8.8` | Reverse DNS for an IPv4 or IPv6 address, plus a check that the hostname resolves back to the same IP |
| `srv` | `srv:_sip._tcp.example.com` | Service records |
| `caa` | `caa:example.com` | Which certificate authorities may issue certificates for the domain |
| `spf` | `spf:example.com` | The SPF record broken into its parts. Counts DNS lookups against the limit of 10, following `include:` and `redirect=`. Flags more than one SPF record, `+all` or `?all`, the deprecated `ptr` mechanism, and unknown terms. |
| `dmarc` | `dmarc:example.com` | The record at `_dmarc.<domain>`, with each tag explained. Checks the policy, `pct`, `rua` reporting, and that `v=DMARC1` comes first. |
| `dkim` | `dkim:selector:example.com` | The key at `<selector>._domainkey.<domain>`. Checks the key and its RSA length, and flags revoked keys (empty `p=`) and testing mode (`t=y`). |
| `blacklist` | `blacklist:1.2.3.4` | Checks an IPv4 address against 14 DNS blacklists. Given a domain, it checks the IPs of the domain's mail servers (or its A records if it has no MX), up to 4 IPs. |
| `dnssec` | `dnssec:example.com` | DNSKEY and DS records, whether a DS key tag matches a DNSKEY, and whether the resolver validated the answer |
| `dns` | `dns:example.com` | SOA, NS, A, AAAA, CNAME, MX, TXT and CAA records, all queried at once |
| `rdap` | `rdap:example.com` | Registration data from the domain's registry over RDAP: registrar, abuse contact, registration, expiry and change dates, status codes, delegated name servers and DNSSEC. Flags an unregistered or expired domain, expiry within 30 days, and hold or pending-delete status. A subdomain is looked up as its registered domain. |

## HTTP API

### `GET /api/lookup`

| Parameter | Required | Description |
|---|---|---|
| `q` | yes | The lookup, in the same format as the search box (at most 300 characters) |
| `server` | no | Resolver as `ip` or `ip:port`; leave it out or pass `default` to use the server default |

```sh
curl 'http://localhost:8080/api/lookup?q=mx:gmail.com&server=1.1.1.1'
```

```json
{
  "command": "mx",
  "query": "gmail.com",
  "server": "1.1.1.1:53",
  "time_ms": 42,
  "headers": ["Pref", "Hostname", "IP Address", "TTL"],
  "rows": [["5", "gmail-smtp-in.l.google.com", "142.250.27.26\n2a00:1450:4025:401::1a", "1h"]],
  "checks": [{"status": "pass", "name": "MX records", "message": "Found 5 MX record(s)"}],
  "response": ";; opcode: QUERY, status: NOERROR ..."
}
```

- `error` is present when the lookup itself failed, for example on a timeout
  or an invalid domain. The response is still `200`, and `rows` and `checks`
  may be partly filled.
- A cell with several values separates them with `\n`.
- The response is `400` for a missing or overlong `q` or an invalid `server`.
  It is `403` when `server` is given but custom resolvers are turned off.

### `GET /api/commands`

Lists the available commands, the default resolver, and whether custom
resolvers are allowed.

## Things to know

- **Spamhaus and some other blacklists refuse queries that come through
  public resolvers** like 1.1.1.1 and 8.8.8.8. These show as `Error` in the
  results rather than as "not listed". For reliable blacklist results, use a
  recursive resolver you run yourself.
- **Blacklist checks only support IPv4.** IPv6 addresses are reported as skipped.
- **DMARC lookups don't fall back to the parent domain.** If a subdomain has
  no `_dmarc` record of its own, the lookup reports that, even if the parent
  domain has one.
- **RDAP lookups go out over HTTPS, not DNS.** They ignore the chosen
  resolver; DNS Dash needs outbound HTTPS to `data.iana.org` and the
  registries' RDAP servers. A few ccTLDs have no RDAP server yet and report an
  error. For thin registries such as `.com`, the registry's record is shown,
  not the registrar's (so registrant details are usually absent).
- **DNSSEC validation relies on the resolver.** It is reported from the
  resolver's AD flag; DNS Dash does not check signatures itself.
- **Custom resolvers turn DNS Dash into a DNS relay.** With
  `-allow-custom-resolver` on (the default), anyone who can reach the app can
  make it send DNS queries to any IP and port. Turn it off when exposing the
  app publicly, and put rate limiting in front of it.
