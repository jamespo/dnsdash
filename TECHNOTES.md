# Technical notes

## Layout

| File | Contents |
|---|---|
| `main.go` | Flag parsing, HTTP server and routes, JSON API handlers, request logging, embedded `web/` files |
| `resolver.go` | `Resolver`, a thin wrapper around `github.com/miekg/dns`, plus helpers to normalise and pick the resolver |
| `lookup.go` | The `Result` and `Check` types, the command registry, query parsing, and the DNS record commands (`mx`, `ns`, `soa`, `ptr`, `dnssec`, `dns`, plus the generic record commands) |
| `mail.go` | Email-related commands: `spf`, `dmarc`, `dkim`, `blacklist` |
| `web/index.html` | The whole front end, as one HTML file with inline CSS and JavaScript and no build step |

The only third-party dependency is `github.com/miekg/dns`. Everything else
uses the standard library.

## Request flow

```
browser ──GET /api/lookup?q=spf:example.com&server=8.8.8.8──▶ handleLookup
   handleLookup: validate q (≤300 chars), normalise server, 30s context
   Run(ctx, resolver, q)
     parseQuery → ("spf", "example.com")
     commandIndex["spf"].Handler(ctx, res, arg, out)  → fills out.Headers/Rows/Checks
     time it, turn any error into out.Error, use empty slices instead of nil
   writeJSON(200, result)
```

Every command returns the same `Result` shape: a table (`Headers` plus
`Rows [][]string`), a list of `Check`s, and optionally the raw response text.
This keeps the front end generic: it renders any command without knowing
anything about it. To add a command, add an entry to `commands` in
`lookup.go`'s `init()`. The command buttons, `/api/commands` and query parsing
all pick it up automatically. Related-lookup suggestions are the one exception:
they are hard-coded in the `related` map in `index.html`.

### Error handling

- A handler returning an error (bad input, timeout, a server error such as
  SERVFAIL or REFUSED) sets `Result.Error`. The HTTP status stays `200`.
- NXDOMAIN is not treated as an error. `Answers` returns it normally and
  `rcodeCheck` turns it into a "Domain exists" FAIL check.
- Smaller problems found during a check (an MX host that doesn't resolve, a
  blacklist refusing the query) become `Check`s, so the rest of the result
  still renders.

## Resolver

`Resolver.Query`:

- Sends a single recursive query (RD=1) over UDP with EDNS0. It advertises a
  4096-byte buffer and sets the DO bit, so the resolver returns the AD flag
  and DNSSEC records.
- Retries over TCP if the UDP answer comes back truncated (TC=1).
- Uses the client timeout (`-timeout`, 5s by default) for each query. The
  request's 30s context covers the whole command.

`Answers` filters the answer section down to the requested record type, so a
CNAME chain doesn't appear in typed results. Handlers that want to show the
chain (the generic record commands) read `qr.Msg.Answer` directly.

`normalizeServer` accepts only IP literals, optionally with a port, and
defaults the port to 53. Hostnames are rejected on purpose, so a user-supplied
resolver can't cause a hostname lookup or point at a name that changes what it
resolves to.

When `-resolver` isn't set, `systemResolver` uses the first nameserver in
`/etc/resolv.conf`. On systemd-resolved systems this is often `127.0.0.53`, a
stub resolver that may hide DNSSEC details or the true answer flags.

## Command details

### Query parsing

`parseQuery` treats the text before the first `:` as the command only when it
is a known command name. Otherwise the whole input is the target: an IP runs
`ptr` and anything else runs `mx`. Because of this, `ptr:2001:db8::1` and
`dkim:selector:domain` work even though the target contains colons.

`cleanDomain` lowercases the input, removes `http(s)://`, any path, query or
fragment, and a trailing dot, then validates the name with `dns.IsDomainName`
and a 253-character limit.

### Concurrency

Handlers fan out with goroutines and a `sync.WaitGroup`, writing each result
into a slot of a pre-sized slice so the output order stays the same from run
to run:

- `mx` and `ns` resolve each host's IPs in parallel. `ns` also queries each
  name server directly for its SOA (non-recursive answers are fine here
  because the server is authoritative).
- `dns` sends all 8 record-type queries at once.
- `blacklist` runs (IPs × lists) queries through a semaphore that allows 16 at
  a time. With 4 IPs and 18 lists that is at most 72 queries.

### SPF

- `findSPF` keeps the TXT records starting with `v=spf1` (case-insensitive).
- `parseSPF` splits each term into a qualifier (`+ - ~ ?`, `+` if none), a name,
  and a value. A term containing `=` is a modifier (`redirect`, `exp`), which
  has no qualifier.
- `countSPFLookups` walks `include:` and `redirect=` recursively, counting the
  terms that cost a DNS lookup (`include a mx ptr exists redirect`; RFC 7208
  §4.6.4).
  - It detects loops with a `seen` set and stops at a depth of 10.
  - A domain reached through an include that has zero or several SPF records
    is reported as an error.
- The check does not evaluate macros (`%{i}` etc.) and does not count the
  "void lookup" limit.

### DMARC

- Looks up the TXT records at `_dmarc.<domain>` and keeps those starting with
  `v=DMARC1`.
- `parseTags` splits on `;` and `=`, keeping tag order so it can check that
  `v` comes first.
- There is no fallback to the organisational domain: that would need the
  Public Suffix List, which isn't included.

### DKIM

- The argument is `selector:domain`, looked up at `<selector>._domainkey.<domain>`.
- The `p=` value is base64-decoded with any whitespace removed, then parsed:
  - as a PKIX `SubjectPublicKeyInfo` first;
  - then as PKCS#1 if that fails;
  - when `k=ed25519`, as a raw 32-byte key instead.
- RSA keys are graded: below 1024 bits FAIL, below 2048 WARN, otherwise PASS.

### Blacklists (DNSBL)

- **Query.** For IPv4 `a.b.c.d`, it asks for the A record of
  `d.c.b.a.<list>`. NXDOMAIN or no answer means the IP is not listed.
- **Reading the reply:**
  - An answer in `127.0.0.0/8` means the IP is listed. The TXT record at the
    same name is fetched for the reason.
  - `127.255.255.x` or any address outside `127/8` means the list refused the
    query. Spamhaus, for example, answers `127.255.255.254` to queries from
    public resolvers. These are reported as `Error`, not as not-listed.
- **Domain targets.** The check runs on the IPv4 addresses of the domain's MX
  hosts, or of the domain itself if it has no MX, removing duplicates and
  stopping at 4 IPs.
- **IPv6.** Not supported. Lists that accept IPv6 use reversed-nibble names
  and different lists.
- The list of blacklists is the `dnsbls` slice in `mail.go`.

### DNSSEC

- Fetches the DNSKEY and DS records for the name and compares DS key tags with
  `DNSKEY.KeyTag()`.
- It does not compute digests or check RRSIGs. The "Validated" check only
  reports the resolver's AD flag.
- A DNSKEY with the SEP flag (257) is labelled KSK; anything else is labelled ZSK.

### Formatting

- `rdata()` gets the record data by removing the header text from `rr.String()`.
- TXT values are joined without the zone-file quoting.
- `formatTTL` shows round values as `d`, `h` or `m`, and anything else in Go
  duration format (`10m42s`).

## Front end

- **Plain DOM.** It builds elements with a small `el()` helper and inserts all
  server data with `append` and `textContent`, never `innerHTML`, so record
  contents can't inject markup.
- **Clickable cells.** `linkify` turns cell text matching IP or hostname
  patterns into links that start a new lookup. It skips IPs in blacklist
  results, where the IP column is the input.
- **Results.** They stack newest first. A placeholder card shows while a
  lookup runs and is replaced in place when the result arrives.
- **State.** `history.replaceState` keeps `?q=&server=` in sync, and `init()`
  replays them when the page loads.
- **Theme.** Colour tokens on `:root` are swapped by a
  `prefers-color-scheme: dark` media query.

## Security considerations

- **Relay risk.** Custom resolvers let any client make the server send
  UDP/TCP DNS queries to any IP and port: a small SSRF and amplification
  vector. Turn them off with `-allow-custom-resolver=false` on public
  deployments. Port and address-range restrictions (such as blocking
  RFC 1918 ranges) are not implemented.
- **Limits that exist:**
  - a 300-character limit on `q`;
  - domain name validation;
  - a 30s limit on each request;
  - a cap of 16 concurrent blacklist queries and at most 4 IPs per
    blacklist lookup.
- **Limits that don't exist:** there is no rate limiting or authentication.
  Put DNS Dash behind a reverse proxy if those are needed.
- **Server timeouts.** Only `ReadHeaderTimeout` is set (10s). Write timeouts
  are left to the per-request context.

## Possible extensions

- Organisational-domain DMARC lookup (needs `golang.org/x/net/publicsuffix`)
- Full DNSSEC chain validation (`dns.RRSIG.Verify`, DS digest computation)
- IPv6 and domain-based blacklists (such as `dbl.spamhaus.org`)
- An SMTP banner and STARTTLS test (`smtp:` command), and an HTTP/HTTPS check
- Tests: table-driven unit tests for `parseQuery`, `parseSPF`, `parseTags`
  and `formatTTL`, and handler tests against a local `dns.Server`
