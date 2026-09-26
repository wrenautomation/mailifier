/**
 * The SMTP handshake a paid verification service runs, from a host of yours.
 *
 * MX lookup → connect on 25 → EHLO → MAIL FROM → RCPT TO <the address> → QUIT. The
 * server's answer to RCPT is the verdict: 250 accepted, 5xx no such user, 4xx "ask
 * later" (greylisting). A second RCPT to a random local part tells catch-all domains
 * apart from real acceptance. No DATA, so nothing is ever delivered.
 *
 * Honest limits: a catch-all domain (most Microsoft 365 tenants) says yes to anything,
 * so the verdict is `catch_all`, not `valid`; an MX that will not talk to us is `risky`,
 * never `invalid`. Both are what the paid services return too. Etiquette: one
 * connection per MX at a time, a gap between probes, a HELO name whose forward and
 * reverse DNS match, and MAIL FROM at that same name so a curious postmaster can look
 * us up. Most clouds close outbound port 25 by default, so this usually runs on one host
 * that can, with everything else asking that host over HTTP (`client.ts`, `server.ts`).
 */
import { randomBytes } from "node:crypto";
import { createConnection, type Socket } from "node:net";
import { DohStatusError, resolve as dohResolve, type Resolver } from "./dns.js";
import type { MailboxProbe, MailboxResult, Verdict } from "./verdict.js";

export const SMTP_PORT = 25;
const CRLF = "\r\n";
const DEFAULT_TIMEOUT_MS = 12_000;
const MAX_MX_TRIED = 3;

/** One line of SMTP conversation, kept for the verdict's `raw` (no addresses beyond ours). */
export interface Exchange {
  sent: string | null;
  code: number;
  reply: string;
}

/** What the wire said, before it is read as a verdict. */
export interface ProbeOutcome {
  result: MailboxResult;
  /** Why, in one word: accepted, rejected, catch_all, catch_all_unknown, greylisted, blocked, unreachable, no_mx, dns_error. */
  reason: string;
  mx: string | null;
  /** The RCPT reply for the address itself, when one was given. */
  code: number | null;
  transcript: Exchange[];
}

/** A connected line-oriented conversation; the real one is a TCP socket, tests hand in a script. */
export interface Conversation {
  /** Next reply (a full, possibly multi-line SMTP response). */
  read(): Promise<string>;
  write(line: string): Promise<void>;
  close(): void;
}
export type Dialer = (host: string, port: number, timeoutMs: number) => Promise<Conversation>;

export interface SmtpProbeOptions {
  /** Our HELO name; forward and reverse DNS should agree on it. */
  helo: string;
  /** MAIL FROM address, defaults to postmaster@helo. */
  mailFrom?: string;
  timeoutMs?: number;
  dial?: Dialer;
  resolver?: Resolver;
  random?: () => string;
  /**
   * What we already know about a domain's catch-all: true = takes any address, false =
   * rejects unknown ones. Saves the extra conversation `probeMailbox` needs when the
   * in-session check is refused. Absent = learn afresh each probe.
   */
  catchAll?: CatchAllMemory;
}

export interface CatchAllMemory {
  get(domain: string): boolean | undefined;
  set(domain: string, acceptsAll: boolean): void;
}

class SmtpReply extends Error {
  constructor(
    readonly code: number,
    readonly text: string,
  ) {
    super(`${code} ${text}`);
    this.name = "SmtpReply";
  }
}

const replyCode = (reply: string) => Number.parseInt(reply.slice(0, 3), 10);
/**
 * "No such user" in the words the big hosts use when the enhanced code is not 5.1.x:
 * Microsoft 365 says "5.4.1 Recipient address rejected: Access denied", consumer
 * Outlook "5.5.0 mailbox unavailable".
 */
const REJECTED_USER =
  /user unknown|no such user|does not exist|unknown user|recipient rejected|recipient address rejected|invalid recipient|no mailbox|mailbox not found|mailbox unavailable|address rejected/i;
const replyClass = (code: number) => Math.floor(code / 100);
/** RFC 3463 enhanced code carried in the text, e.g. "5.1.1". */
const enhanced = (reply: string) => /\b([245])\.(\d{1,3})\.(\d{1,3})\b/.exec(reply);

/**
 * MX hosts in priority order (lowest number first), falling back to the domain's own A
 * record when there is none, as mail does. Empty = nothing to connect to.
 */
export async function mailHosts(domain: string, resolver: Resolver): Promise<string[]> {
  const mx = (await resolver(domain, "MX"))
    .map((rr) => {
      const [priority, host] = rr.trim().split(/\s+/);
      return { priority: Number(priority), host: (host ?? "").replace(/\.$/, "").toLowerCase() };
    })
    .filter((r) => r.host !== "" && r.host !== ".")
    .sort((a, b) => a.priority - b.priority);
  if (mx.length > 0) return [...new Set(mx.map((r) => r.host))];
  const a = await resolver(domain, "A");
  return a.length > 0 ? [domain] : [];
}

/** Talk to one MX about one address. Throws SmtpReply for a refusal before RCPT, or a socket error. */
async function converse(
  conv: Conversation,
  email: string,
  opts: Required<Pick<SmtpProbeOptions, "helo" | "mailFrom" | "random">>,
  transcript: Exchange[],
): Promise<{ code: number; reply: string; randomAccepted: boolean | null }> {
  const step = async (line: string | null): Promise<{ code: number; reply: string }> => {
    if (line !== null) await conv.write(line);
    const reply = await conv.read();
    const code = replyCode(reply);
    transcript.push({ sent: line, code, reply: reply.slice(0, 200) });
    return { code, reply };
  };
  const expect = async (line: string | null, ok: number) => {
    const r = await step(line);
    if (r.code !== ok) throw new SmtpReply(r.code, r.reply);
    return r;
  };
  await expect(null, 220);
  await expect(`EHLO ${opts.helo}`, 250);
  await expect(`MAIL FROM:<${opts.mailFrom}>`, 250);
  const rcpt = await step(`RCPT TO:<${email}>`);
  let randomAccepted: boolean | null = null;
  if (replyClass(rcpt.code) === 2) {
    const domain = email.slice(email.lastIndexOf("@") + 1);
    const probe = await step(`RCPT TO:<${opts.random()}@${domain}>`);
    // Only a 2xx or a "no such user" answers the question. Microsoft 365 says "452 Too
    // many recipients" to any second RCPT from us: that is no answer at all.
    randomAccepted = replyClass(probe.code) === 2 ? true : isUserReject(probe) ? false : null;
  }
  try {
    await conv.write("QUIT");
  } catch {
    // Already said what we needed.
  }
  conv.close();
  return { code: rcpt.code, reply: rcpt.reply, randomAccepted };
}

/** A 5xx that means "no such mailbox", not a policy refusal of us. */
const isUserReject = ({ code, reply }: { code: number; reply: string }) =>
  replyClass(code) === 5 && (enhanced(reply)?.[2] === "1" || REJECTED_USER.test(reply));

/** Read the RCPT answer as a verdict. */
function readRcpt(
  code: number,
  reply: string,
  randomAccepted: boolean | null,
): Pick<ProbeOutcome, "result" | "reason"> {
  const klass = replyClass(code);
  if (klass === 2) {
    if (randomAccepted === null) return { result: "risky", reason: "catch_all_unknown" };
    return randomAccepted
      ? { result: "catch_all", reason: "catch_all" }
      : { result: "valid", reason: "accepted" };
  }
  const enh = enhanced(reply);
  if (klass === 5) {
    // 5.1.x = bad mailbox/address: the definitive "no such user". Other 5xx (5.7.x
    // policy, 554 blocked, 552 quota) say something about us or the box, not the address.
    if (enh?.[2] === "1" || REJECTED_USER.test(reply))
      return { result: "invalid", reason: "rejected" };
    return { result: "risky", reason: "blocked" };
  }
  return { result: "risky", reason: "greylisted" };
}

/**
 * Probe one address: the first MX that will talk decides. An MX that refuses us
 * before RCPT (policy 5xx at EHLO/MAIL FROM) or cannot be reached is skipped for the
 * next; when every one does, the verdict is risky, with the reason.
 */
export async function probeMailbox(email: string, opts: SmtpProbeOptions): Promise<ProbeOutcome> {
  const resolver = opts.resolver ?? ((n, t) => dohResolve(n, t));
  const dial = opts.dial ?? dialTcp;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const conv = {
    helo: opts.helo,
    mailFrom: opts.mailFrom ?? `postmaster@${opts.helo}`,
    random: opts.random ?? (() => `wren-${randomBytes(6).toString("hex")}`),
  };
  const domain = email.slice(email.lastIndexOf("@") + 1).toLowerCase();
  const transcript: Exchange[] = [];
  let hosts: string[];
  try {
    hosts = await mailHosts(domain, resolver);
  } catch (err) {
    if (err instanceof DohStatusError) return dnsError(err, transcript);
    throw err;
  }
  if (hosts.length === 0)
    return { result: "invalid", reason: "no_mx", mx: null, code: null, transcript };

  let lastReason = "unreachable";
  for (const host of hosts.slice(0, MAX_MX_TRIED)) {
    let session: Conversation;
    try {
      session = await dial(host, SMTP_PORT, timeoutMs);
    } catch (err) {
      transcript.push({ sent: null, code: 0, reply: `connect ${host}: ${errorName(err)}` });
      lastReason = "unreachable";
      continue;
    }
    try {
      const said = await converse(session, email, conv, transcript);
      let randomAccepted = said.randomAccepted;
      if (isUserReject(said)) opts.catchAll?.set(domain, false);
      if (replyClass(said.code) === 2 && randomAccepted === null) {
        randomAccepted =
          opts.catchAll?.get(domain) ??
          (await askRandomAlone(host, domain, { dial, timeoutMs, conv, transcript }));
      }
      if (randomAccepted !== null) opts.catchAll?.set(domain, randomAccepted);
      return {
        ...readRcpt(said.code, said.reply, randomAccepted),
        mx: host,
        code: said.code,
        transcript,
      };
    } catch (err) {
      session.close();
      if (err instanceof SmtpReply) {
        // A greeting or envelope refusal: about us, not the address. Try the next MX.
        lastReason = replyClass(err.code) === 4 ? "greylisted" : "blocked";
        continue;
      }
      transcript.push({ sent: null, code: 0, reply: `${host}: ${errorName(err)}` });
      lastReason = "unreachable";
    }
  }
  return { result: "risky", reason: lastReason, mx: null, code: null, transcript };
}

/**
 * The catch-all question on its own conversation, the made-up address as the first and
 * only RCPT: hosts that refuse a second RCPT (Microsoft 365) still answer a first one.
 * true = takes any address, false = rejects unknown ones, null = still no answer.
 */
async function askRandomAlone(
  host: string,
  domain: string,
  o: {
    dial: Dialer;
    timeoutMs: number;
    conv: Required<Pick<SmtpProbeOptions, "helo" | "mailFrom" | "random">>;
    transcript: Exchange[];
  },
): Promise<boolean | null> {
  let session: Conversation;
  try {
    session = await o.dial(host, SMTP_PORT, o.timeoutMs);
  } catch (err) {
    o.transcript.push({ sent: null, code: 0, reply: `connect ${host}: ${errorName(err)}` });
    return null;
  }
  try {
    const said = await converse(session, `${o.conv.random()}@${domain}`, o.conv, o.transcript);
    if (replyClass(said.code) === 2) return true;
    return isUserReject(said) ? false : null;
  } catch (err) {
    session.close();
    o.transcript.push({ sent: null, code: 0, reply: `${host}: ${errorName(err)}` });
    return null;
  }
}

/**
 * The resolver answered but the domain's DNS is broken (SERVFAIL, REFUSED): about the
 * domain, not the prober, so a risky verdict to retry later, not an error. A resolver
 * that cannot be reached at all stays an error: every probe would fail the same way.
 */
const dnsError = (err: DohStatusError, transcript: Exchange[]): ProbeOutcome => ({
  result: "risky",
  reason: "dns_error",
  mx: null,
  code: null,
  transcript: [...transcript, { sent: null, code: 0, reply: err.message }],
});

const errorName = (err: unknown) =>
  err instanceof Error
    ? `${err.name}${(err as NodeJS.ErrnoException).code ? ` ${(err as NodeJS.ErrnoException).code}` : ""}`
    : String(err);

/** The real thing: a TCP socket read line by line, multi-line replies joined. */
export const dialTcp: Dialer = (host, port, timeoutMs) =>
  new Promise((resolveConn, reject) => {
    const socket: Socket = createConnection({ host, port });
    let buffer = "";
    let waiting: { resolve: (s: string) => void; reject: (e: Error) => void } | null = null;
    const fail = (err: Error) => {
      if (waiting) {
        waiting.reject(err);
        waiting = null;
      } else reject(err);
      socket.destroy();
    };
    socket.setTimeout(timeoutMs, () =>
      fail(Object.assign(new Error("smtp timeout"), { code: "ETIMEDOUT" })),
    );
    socket.on("error", fail);
    socket.on("close", () => fail(Object.assign(new Error("closed"), { code: "ECONNRESET" })));
    const pump = () => {
      // A reply is complete when its last line has a space after the code ("250 ok"),
      // continuation lines use a dash ("250-SIZE").
      const lines = buffer.split(CRLF);
      const end = lines.findIndex((l) => /^\d{3} /.test(l) || (l.length > 0 && /^\d{3}$/.test(l)));
      if (end < 0 || !waiting) return;
      const reply = lines.slice(0, end + 1).join("\n");
      buffer = lines.slice(end + 1).join(CRLF);
      const w = waiting;
      waiting = null;
      w.resolve(reply);
    };
    socket.on("data", (chunk) => {
      buffer += chunk.toString("latin1");
      pump();
    });
    socket.once("connect", () =>
      resolveConn({
        read: () =>
          new Promise<string>((res, rej) => {
            waiting = { resolve: res, reject: rej };
            pump();
          }),
        write: (line) =>
          new Promise<void>((res, rej) =>
            socket.write(`${line}${CRLF}`, (err) => (err ? rej(err) : res())),
          ),
        close: () => {
          socket.removeAllListeners("close");
          socket.end();
          socket.destroy();
        },
      }),
    );
  });

export interface SmtpProbeSettings extends SmtpProbeOptions {
  /** Least time between two probes at the same MX; ours is a guest there. */
  perHostGapMs?: number;
  /**
   * Conversations at once with one MX host (default 1). Each lane keeps the gap.
   * Worth more than 1 only for the big shared inbound fleets (`bigProviderLanes`),
   * where thousands of domains queue behind one host name.
   */
  lanesFor?: (host: string) => number;
  sleep?: (ms: number) => Promise<void>;
}

/**
 * Shared inbound fleets that front thousands of domains under one host name and take
 * mail from the whole internet at once: Google, Microsoft, Proofpoint, Mimecast.
 */
const BIG_PROVIDER =
  /(^|\.)(google\.com|googlemail\.com|outlook\.com|pphosted\.com|ppe-hosted\.com|mimecast\.com)$/;

export function isBigProvider(host: string): boolean {
  return BIG_PROVIDER.test(host.toLowerCase().replace(/\.$/, ""));
}

/** `lanesFor` that gives the big shared fleets `lanes` and everyone else one. */
export function bigProviderLanes(lanes: number): (host: string) => number {
  const n = Math.max(1, Math.floor(lanes));
  return (host) => (isBigProvider(host) ? n : 1);
}

/**
 * A bounded, expiring `CatchAllMemory`: the oldest entry goes when full, an entry
 * older than `ttlMs` is forgotten (a domain can change its mail setup).
 */
export class CatchAllCache implements CatchAllMemory {
  private readonly entries = new Map<string, { acceptsAll: boolean; at: number }>();

  constructor(
    private readonly max = 50_000,
    private readonly ttlMs = 86_400_000,
    private readonly now: () => number = Date.now,
  ) {}

  get(domain: string): boolean | undefined {
    const e = this.entries.get(domain);
    if (!e) return undefined;
    if (this.now() - e.at > this.ttlMs) {
      this.entries.delete(domain);
      return undefined;
    }
    return e.acceptsAll;
  }

  set(domain: string, acceptsAll: boolean): void {
    this.entries.delete(domain);
    this.entries.set(domain, { acceptsAll, at: this.now() });
    if (this.entries.size > this.max) {
      const oldest = this.entries.keys().next().value;
      if (oldest !== undefined) this.entries.delete(oldest);
    }
  }
}

/**
 * The probe over `probeMailbox`, serialising per MX host with a gap between them: one
 * conversation at a time with any given server, because we are a guest there.
 */
export class SmtpProbe implements MailboxProbe {
  readonly name = "smtp";
  private readonly lastByHost = new Map<string, Promise<void>>();
  private readonly turnsByHost = new Map<string, number>();
  private readonly gapMs: number;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly catchAll: CatchAllMemory;

  constructor(private readonly opts: SmtpProbeSettings) {
    this.catchAll = opts.catchAll ?? new CatchAllCache();
    this.gapMs = opts.perHostGapMs ?? 1_500;
    this.sleep = opts.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
  }

  async verify(email: string): Promise<Verdict> {
    const domain = email.slice(email.lastIndexOf("@") + 1).toLowerCase();
    const resolver = this.opts.resolver ?? ((n, t) => dohResolve(n, t));
    // The queue key is the primary MX: what we are actually about to knock on.
    let hosts: string[];
    try {
      hosts = await mailHosts(domain, resolver);
    } catch (err) {
      if (err instanceof DohStatusError) return this.verdictOf(dnsError(err, []));
      throw err;
    }
    const host = hosts[0] ?? domain;
    // Round-robin over the host's lanes; each lane is its own queue with its own gap.
    const turns = this.turnsByHost.get(host) ?? 0;
    this.turnsByHost.set(host, turns + 1);
    const key = `${host}#${turns % Math.max(1, this.opts.lanesFor?.(host) ?? 1)}`;
    const previous = this.lastByHost.get(key) ?? Promise.resolve();
    const turn = previous.then(async () => {
      const outcome = await probeMailbox(email, {
        ...this.opts,
        resolver,
        catchAll: this.catchAll,
      });
      await this.sleep(this.gapMs);
      return outcome;
    });
    this.lastByHost.set(
      key,
      turn.then(
        () => undefined,
        () => undefined,
      ),
    );
    return this.verdictOf(await turn);
  }

  private verdictOf(outcome: ProbeOutcome): Verdict {
    return {
      result: outcome.result,
      raw: {
        reason: outcome.reason,
        mx: outcome.mx,
        code: outcome.code,
        helo: this.opts.helo,
        transcript: outcome.transcript,
      },
    };
  }
}
