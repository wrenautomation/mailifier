/** The SMTP handshake read as verdicts, over scripted conversations (no sockets). */

import { describe, expect, it } from "vitest";
import { DohError, DohStatusError, type Resolver } from "./dns.js";
import {
  bigProviderLanes,
  CatchAllCache,
  type Conversation,
  type Dialer,
  isBigProvider,
  mailHosts,
  probeMailbox,
  SmtpProbe,
} from "./smtp.js";

/** A server that answers each command from a table; `banner` first. */
function script(
  banner: string,
  answers: Record<string, string | ((line: string) => string)>,
): Conversation & { lines: string[] } {
  const lines: string[] = [];
  let pending: string | null = banner;
  return {
    lines,
    async read() {
      if (pending === null) throw new Error("nothing to read");
      const r = pending;
      pending = null;
      return r;
    },
    async write(line) {
      lines.push(line);
      const verb = line.split(/[ :]/, 1)[0] as string;
      const answer = answers[verb] ?? answers[line];
      if (answer === undefined) throw new Error(`no scripted answer for ${line}`);
      pending = typeof answer === "function" ? answer(line) : answer;
    },
    close() {},
  };
}

const google = (rcpt: (line: string) => string) =>
  script("220 mx.example ESMTP", {
    EHLO: "250-mx.example at your service\n250 SIZE 1000",
    MAIL: "250 2.1.0 OK",
    RCPT: rcpt,
    QUIT: "221 bye",
  });

const resolver: Resolver = async (name, type) => {
  if (type === "MX" && name === "acme.example")
    return ["20 mx2.acme.example.", "10 mx1.acme.example."];
  if (type === "MX" && name === "bare.example") return [];
  if (type === "A" && name === "bare.example") return ["203.0.113.5"];
  return [];
};
const opts = (dial: Dialer) => ({ helo: "probe.test", dial, resolver, random: () => "zz-random" });

/** Microsoft 365 as we meet it: answers the first RCPT, says 452 to any second one. */
const microsoft = (first: (line: string) => string) => {
  let rcpts = 0;
  return script("220 outlook ESMTP", {
    EHLO: "250 outlook.example",
    MAIL: "250 2.1.0 Sender OK",
    RCPT: (line) => {
      rcpts += 1;
      return rcpts === 1 ? first(line) : "452 4.5.3 Too many recipients";
    },
    QUIT: "221 bye",
  });
};
const tenant = (acceptsAll: boolean | "silent") => (line: string) =>
  !line.includes("zz-random")
    ? "250 2.1.5 Recipient OK"
    : acceptsAll === "silent"
      ? "451 4.7.500 Try again later"
      : acceptsAll
        ? "250 2.1.5 Recipient OK"
        : "550 5.4.1 Recipient address rejected: Access denied";

describe("the catch-all check when a host refuses a second RCPT", () => {
  const run = async (acceptsAll: boolean | "silent", catchAll?: CatchAllCache) => {
    let dials = 0;
    const out = await probeMailbox("jane@acme.example", {
      ...opts(async () => {
        dials += 1;
        return microsoft(tenant(acceptsAll));
      }),
      ...(catchAll ? { catchAll } : {}),
    });
    return { out, dials };
  };

  it("asks again on a fresh conversation: rejected there = valid", async () => {
    const { out, dials } = await run(false);
    expect(out).toMatchObject({ result: "valid", reason: "accepted", mx: "mx1.acme.example" });
    expect(dials).toBe(2);
  });

  it("accepted there = catch_all", async () => {
    expect((await run(true)).out).toMatchObject({ result: "catch_all", reason: "catch_all" });
  });

  it("no answer there either = risky, never valid", async () => {
    expect((await run("silent")).out).toMatchObject({
      result: "risky",
      reason: "catch_all_unknown",
    });
  });

  it("remembers the domain's answer: one extra conversation per domain", async () => {
    const memory = new CatchAllCache();
    expect((await run(false, memory)).dials).toBe(2);
    const again = await run(false, memory);
    expect(again).toMatchObject({ dials: 1, out: { result: "valid" } });
  });
});

describe("CatchAllCache", () => {
  it("forgets after its ttl and drops the oldest when full", () => {
    let now = 0;
    const cache = new CatchAllCache(2, 1_000, () => now);
    cache.set("a.example", true);
    cache.set("b.example", false);
    cache.set("c.example", true);
    expect(cache.get("a.example")).toBeUndefined();
    expect(cache.get("b.example")).toBe(false);
    now = 1_001;
    expect(cache.get("c.example")).toBeUndefined();
  });
});

describe("mailHosts", () => {
  it("orders MX by priority and strips the dot", async () =>
    expect(await mailHosts("acme.example", resolver)).toEqual([
      "mx1.acme.example",
      "mx2.acme.example",
    ]));
  it("falls back to the A record, then nothing", async () => {
    expect(await mailHosts("bare.example", resolver)).toEqual(["bare.example"]);
    expect(await mailHosts("nowhere.example", resolver)).toEqual([]);
  });
});

describe("probeMailbox", () => {
  it("accepted and the random probe refused = valid", async () => {
    const conv = google((line) =>
      line.includes("zz-random") ? "550 5.1.1 no such user" : "250 2.1.5 OK",
    );
    const out = await probeMailbox(
      "jane@acme.example",
      opts(async () => conv),
    );
    expect(out).toMatchObject({
      result: "valid",
      reason: "accepted",
      mx: "mx1.acme.example",
      code: 250,
    });
    expect(conv.lines).toEqual([
      "EHLO probe.test",
      "MAIL FROM:<postmaster@probe.test>",
      "RCPT TO:<jane@acme.example>",
      "RCPT TO:<zz-random@acme.example>",
      "QUIT",
    ]);
  });

  it("everything accepted = catch_all", async () => {
    const out = await probeMailbox(
      "jane@acme.example",
      opts(async () => google(() => "250 2.1.5 OK")),
    );
    expect(out).toMatchObject({ result: "catch_all", reason: "catch_all" });
  });

  it.each([
    ["550-5.1.1 The email account that you tried to reach does not exist.", "invalid", "rejected"],
    ["550 5.4.1 Recipient address rejected: Access denied.", "invalid", "rejected"],
    ["550 5.5.0 Requested action not taken: mailbox unavailable", "invalid", "rejected"],
    ["550 5.7.1 Service unavailable, client blocked", "risky", "blocked"],
    ["450 4.2.0 Greylisted, try again later", "risky", "greylisted"],
  ])("%s -> %s", async (reply, result, reason) => {
    const out = await probeMailbox(
      "jane@acme.example",
      opts(async () => google(() => reply)),
    );
    expect(out).toMatchObject({ result, reason, code: Number(reply.slice(0, 3)) });
  });

  it("moves to the next MX when the first refuses the greeting, and is risky when all do", async () => {
    const dialed: string[] = [];
    const refusing = script("554 no service for you", {});
    const out = await probeMailbox(
      "jane@acme.example",
      opts(async (host) => {
        dialed.push(host);
        return host === "mx1.acme.example" ? refusing : google(() => "250 OK");
      }),
    );
    expect(dialed).toEqual(["mx1.acme.example", "mx2.acme.example"]);
    expect(out).toMatchObject({ result: "catch_all", mx: "mx2.acme.example" });

    const allDown = await probeMailbox(
      "jane@acme.example",
      opts(async () => {
        throw Object.assign(new Error("timeout"), { code: "ETIMEDOUT" });
      }),
    );
    expect(allDown).toMatchObject({ result: "risky", reason: "unreachable", mx: null });
    expect(allDown.transcript.map((x) => x.reply)).toEqual([
      "connect mx1.acme.example: Error ETIMEDOUT",
      "connect mx2.acme.example: Error ETIMEDOUT",
    ]);
  });

  it("a domain with no mail routing is invalid without a connection", async () => {
    const out = await probeMailbox(
      "x@nowhere.example",
      opts(async () => {
        throw new Error("must not dial");
      }),
    );
    expect(out).toMatchObject({ result: "invalid", reason: "no_mx" });
  });
});

describe("SmtpProbe", () => {
  it("serialises probes per MX with a gap and reports the transcript as raw", async () => {
    const order: string[] = [];
    const slept: number[] = [];
    const v = new SmtpProbe({
      helo: "probe.test",
      resolver,
      random: () => "zz-random",
      perHostGapMs: 700,
      sleep: async (ms) => {
        slept.push(ms);
      },
      dial: async (host) => {
        order.push(`dial ${host}`);
        return google((line) => (line.includes("zz-random") ? "550 5.1.1 nope" : "250 OK"));
      },
    });
    const [a, b] = await Promise.all([v.verify("a@acme.example"), v.verify("b@acme.example")]);
    expect(a.result).toBe("valid");
    expect(b.result).toBe("valid");
    expect(slept).toEqual([700, 700]);
    expect(a.raw).toMatchObject({ reason: "accepted", mx: "mx1.acme.example", helo: "probe.test" });
    expect((a.raw.transcript as unknown[]).length).toBeGreaterThan(3);
  });

  it("gives a big shared host several lanes, each with its own gap", async () => {
    let open = 0;
    let peak = 0;
    const v = new SmtpProbe({
      helo: "probe.test",
      resolver: async (_name, type) => (type === "MX" ? ["10 aspmx.l.google.com."] : []),
      random: () => "zz-random",
      perHostGapMs: 0,
      lanesFor: bigProviderLanes(3),
      sleep: async () => {},
      dial: async () => {
        open += 1;
        peak = Math.max(peak, open);
        await new Promise((r) => setTimeout(r, 10));
        open -= 1;
        return google((line) => (line.includes("zz-random") ? "550 5.1.1 nope" : "250 OK"));
      },
    });
    await Promise.all(["a", "b", "c", "d", "e", "f"].map((u) => v.verify(`${u}@acme.example`)));
    expect(peak).toBe(3);
  });

  it("reads a domain's broken DNS as risky, but a dead resolver as an error", async () => {
    const probe = (err: Error) =>
      new SmtpProbe({
        helo: "probe.test",
        resolver: async () => {
          throw err;
        },
        sleep: async () => {},
        dial: async () => {
          throw new Error("never dialed");
        },
      });
    const v = await probe(new DohStatusError("DNS status 2 for MX broken.example")).verify(
      "a@broken.example",
    );
    expect(v).toMatchObject({ result: "risky", raw: { reason: "dns_error", mx: null } });
    await expect(probe(new DohError("HTTP 429")).verify("a@broken.example")).rejects.toThrow(
      DohError,
    );
  });

  it("knows the big shared fleets by host name", () => {
    expect(isBigProvider("aspmx.l.google.com.")).toBe(true);
    expect(isBigProvider("acme-com.mail.protection.outlook.com")).toBe(true);
    expect(isBigProvider("mx1-us1.ppe-hosted.com")).toBe(true);
    expect(isBigProvider("us-smtp-inbound-1.mimecast.com")).toBe(true);
    expect(isBigProvider("mail.notgoogle.com")).toBe(false);
    expect(bigProviderLanes(4)("mx.acme.example")).toBe(1);
  });
});
