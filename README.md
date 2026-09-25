# mailifier

Ask a mail server whether an address exists. No mail is ever sent.

This is the handshake the paid verification services run, from a host of yours:
MX lookup → connect on port 25 → `EHLO` → `MAIL FROM` → `RCPT TO <the address>` →
`QUIT`. The server's answer to `RCPT` is the verdict. There is no `DATA`, so nothing
is ever delivered.

Zero runtime dependencies. Node 22+.

## Install

```sh
pnpm add mailifier
```

## Use it

```ts
import { LocalChecker, SmtpProbe } from "mailifier";

// Stage 1: free, no sockets. Syntax, typosquats, disposable providers, MX routing.
const local = await new LocalChecker().check("jane@acme.com");
if (!local.passed) return local.failure; // "no_mx", "syntax: …", "disposable_domain"

// Stage 2: ask the mail server.
const probe = new SmtpProbe({ helo: "probe.example.com" });
const verdict = await probe.verify("jane@acme.com");
// { result: "valid", raw: { reason: "accepted", mx: "…", code: 250, transcript: [ … ] } }
```

## The four answers

| result | means |
| --- | --- |
| `valid` | the server accepted the address |
| `invalid` | the server refused it by name, or the domain takes no mail at all |
| `catch_all` | the domain accepts everything, so acceptance proves nothing |
| `risky` | nobody would tell us: greylisting, a refused connection, a policy block |

Only `valid` and `invalid` are facts. `catch_all` is common on Microsoft 365 tenants.
`risky` is about the conversation, never about the address — retry it later.

## Running it somewhere that can

Most clouds block outbound port 25 until you ask them to stop. So the usual shape is
one small host that can talk SMTP, and everything else asking it over HTTP.

On that host:

```sh
PROBE_TOKEN=… PROBE_HELO=probe.example.com npx mailifier
```

Everywhere else:

```ts
import { RemoteProbe } from "mailifier";
const probe = new RemoteProbe(process.env.PROBE_URL, process.env.PROBE_TOKEN);
```

Both satisfy `MailboxProbe`, so the calling code never knows which one it has.

The server is bearer-authenticated, caps calls in flight (`PROBE_MAX_IN_FLIGHT`,
default 8; beyond it **429**; `RemoteProbe` waits and retries a 429 for about a minute
before it gives up), and runs a canary before
every verdict: if port 25 is not open from this host it answers **503**, never a
`risky` verdict. A closed port is the host's problem, not the mailbox's — and a
verifier that quietly reports `risky` for a working mailbox is worse than one that
stops.

Each MX host gets one conversation at a time with a gap between probes
(`PROBE_HOST_GAP_MS`, default 1500). Google, Microsoft, Proofpoint and Mimecast front
thousands of domains under one host name, so a list heavy in them queues behind that one
host; `PROBE_BIG_HOST_LANES` (default 1) gives those fleets that many conversations at
once, each with its own gap.

`GET /healthz` → `{ ok, in_flight, port_25 }`.

The published package also carries `dist/mailifier.mjs`: the whole server in one file,
to drop on a box that has node and no npm. `pnpm bundle` rebuilds it.

## Being a good guest

- One conversation per MX at a time, with a gap between them (`perHostGapMs`, 1.5s).
- `helo` should be a name whose forward and reverse DNS agree, and `MAIL FROM` is
  `postmaster@` that name, so a curious postmaster can look you up. Use a name you
  do not send real mail from.
- At most three MX hosts tried per address.
- DNS goes over HTTPS (Cloudflare), so it works in a container with no resolver.

## Interfaces

`MailboxProbe` is the only thing worth depending on:

```ts
interface MailboxProbe {
  readonly name: string;
  verify(email: string): Promise<Verdict>;
}
```

Deliberately not on it: whether a verdict may be trusted, and whether it costs money.
That is your policy about a probe, not something a probe knows about itself.

Every network edge is injectable — `dial`, `resolver`, `fetch`, `sleep` — so the tests
run with no sockets and no DNS.

## Testing against it

`src/smtp.test.ts` shows the pattern: hand `probeMailbox` a scripted `Conversation`
and assert the verdict it reads out of the replies.
