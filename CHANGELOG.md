# Changelog

## 0.1.0 — unreleased

First release. Extracted from a working email system, where it replaced a paid
verification service.

- `SmtpProbe` — the MX → `EHLO` → `MAIL FROM` → `RCPT TO` → `QUIT` handshake, with a
  second `RCPT` to a random local part to tell catch-all domains from real acceptance.
  One conversation per MX at a time, with a gap between them.
- `LocalChecker` — stage 1: syntax, typosquats, disposable providers, MX routing,
  null MX, A/AAAA fallback. No sockets.
- `RemoteProbe` + `makeProbeServer` — the same verdicts from a host that can open
  port 25, for callers that cannot. Bearer-authenticated, capped in flight, and a
  port-25 canary that answers 503 rather than inventing a `risky` verdict.
- Zero runtime dependencies. Every network edge injectable.
