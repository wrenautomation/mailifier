/** The SMTP handshake read as verdicts, over scripted conversations (no sockets). */

import { describe, expect, it } from "vitest";
import type { Resolver } from "./dns.js";
import { type Conversation, type Dialer, mailHosts, probeMailbox, SmtpProbe } from "./smtp.js";

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
});
