# dig-download — development log

Durable realizations worth keeping. Context, not a change diary.

## `format!("{host}:{port}").parse::<SocketAddr>()` silently bans IPv6

The socket-address grammar requires an IPv6 literal to be **bracketed** (`[2001:db8::1]:9444`). Composing
`host:port` from a bare IPv6 host and parsing it back therefore fails with `invalid socket address
syntax` — and it fails BEFORE any socket is opened, so the symptom is a transport error with no dial in
any packet capture.

This killed the whole #836 read leg: an AWS holder advertised `::ffff:172.31.79.22`, the metadata probe
turned it into `"::ffff:172.31.79.22:9444"`, and every confirmed holder was declared unusable → the read
404'd. The upstream candidate was correct all along (dig-node logged the properly bracketed
`[::ffff:172.31.79.22]:9444`); the corruption was purely this string round trip inside dig-download.

Rule: parse the host as an `IpAddr` and build `SocketAddr::new(ip, port)`. Never let a socket address
pass through the text grammar in the middle of a program. Rendering back to text goes through
`SocketAddr::to_string()` (or `addr::display`), which brackets correctly. Both live in `src/addr.rs`.

## One bad candidate must not condemn a holder

The same bug was only fatal because the dial considered a provider's FIRST address and nothing else —
the record ALSO carried a perfectly dialable `172.31.79.22:9444` that was never tried. §5.2 is IPv6-first
with IPv4 **fallback**, which means iterating: every candidate (v6, then v4, then relay-only), each
failure logged with the address it came from, and "unreachable" reported only once the list is exhausted.
