/** Stage-1 local checks (fake resolver, no network). */

import { describe, expect, it } from "vitest";
import { type DnsType, DohError, DohStatusError, type Resolver } from "./dns.js";
import { LocalChecker } from "./local.js";

type Answers = Record<string, string[] | Error>;
const key = (name: string, rtype: DnsType) => `${name}/${rtype}`;
function makeResolver(answers: Answers, calls?: string[]): Resolver {
  return async (name, rtype) => {
    calls?.push(key(name, rtype));
    const result = answers[key(name, rtype)];
    if (result instanceof Error) throw result;
    return result ?? [];
  };
}
const checkerWithMx = (domain = "foo.com") =>
  new LocalChecker(makeResolver({ [key(domain, "MX")]: ["10 mail.foo.com."] }));

describe("passing", () => {
  it("clean business address", async () => {
    const r = await checkerWithMx().check("jane@foo.com");
    expect(r.passed).toBe(true);
    expect(r.flags).toEqual([]);
  });
  it("clean business address carries MX evidence", async () => {
    const r = await checkerWithMx().check("jane@foo.com");
    expect(r.mxHosts).toEqual(["mail.foo.com"]);
    expect(r.mxPath).toBe("mx");
  });
  it("role account passes with flag", async () => {
    const r = await checkerWithMx().check("info@foo.com");
    expect(r.passed).toBe(true);
    expect(r.flags).toContain("role_account");
  });
  it("role detection ignores plus tag", async () =>
    expect((await checkerWithMx().check("info+niche@foo.com")).flags).toContain("role_account"));
  it("freemail passes with flag", async () => {
    const r = await new LocalChecker(
      makeResolver({ [key("gmail.com", "MX")]: ["5 gmail-smtp.l.google.com."] }),
    ).check("jane.doe@gmail.com");
    expect(r.passed).toBe(true);
    expect(r.flags).toContain("freemail");
  });
  it("A record fallback when no MX", async () => {
    const r = await new LocalChecker(
      makeResolver({ [key("foo.com", "MX")]: [], [key("foo.com", "A")]: ["93.184.216.34"] }),
    ).check("jane@foo.com");
    expect(r.passed).toBe(true);
    expect(r.flags).toContain("mx_fallback");
    expect(r.mxPath).toBe("a");
    expect(r.mxHosts).toEqual([]); // no real MX host: routing is direct
  });
  it("AAAA record fallback when no MX or A", async () => {
    const r = await new LocalChecker(
      makeResolver({
        [key("foo.com", "MX")]: [],
        [key("foo.com", "A")]: [],
        [key("foo.com", "AAAA")]: ["2606:2800::1"],
      }),
    ).check("jane@foo.com");
    expect(r.passed).toBe(true);
    expect(r.flags).toContain("mx_fallback");
    expect(r.mxPath).toBe("aaaa");
  });
  it("DNS transport error passes with mx_unresolved", async () => {
    const r = await new LocalChecker(
      makeResolver({ [key("foo.com", "MX")]: new DohError("boom") }),
    ).check("jane@foo.com");
    expect(r.passed).toBe(true);
    expect(r.flags).toContain("mx_unresolved");
    expect(r.mxHosts).toEqual([]);
    expect(r.mxPath).toBeNull();
  });
  it("DoH status error passes with mx_unresolved", async () => {
    const r = await new LocalChecker(
      makeResolver({ [key("foo.com", "MX")]: new DohStatusError("SERVFAIL") }),
    ).check("jane@foo.com");
    expect(r.passed).toBe(true);
    expect(r.flags).toContain("mx_unresolved");
  });
  it("DoH status error on the fallback lookup fails open", async () => {
    const r = await new LocalChecker(
      makeResolver({
        [key("foo.com", "MX")]: [],
        [key("foo.com", "A")]: new DohStatusError("REFUSED"),
      }),
    ).check("jane@foo.com");
    expect(r.passed).toBe(true);
    expect(r.flags).toContain("mx_unresolved");
  });
  it("a non-DoH resolver bug propagates", async () =>
    expect(
      new LocalChecker(makeResolver({ [key("foo.com", "MX")]: new RangeError("malformed") })).check(
        "jane@foo.com",
      ),
    ).rejects.toThrow(RangeError));
});

describe("failing", () => {
  it("syntax failure includes reason", async () =>
    expect((await new LocalChecker(makeResolver({})).check("jane@@foo.com")).failure).toMatch(
      /^syntax:/,
    ));
  it.each([
    ["jane@gmial.com", "typo_domain"],
    ["jane@mailinator.com", "disposable_domain"],
  ])("%s -> %s", async (email, failure) =>
    expect((await new LocalChecker(makeResolver({})).check(email)).failure).toBe(failure),
  );
  it("no MX and no A record", async () => {
    const r = await new LocalChecker(makeResolver({})).check("jane@deaddomain.example");
    expect(r.failure).toBe("no_mx");
    expect(r.mxHosts).toEqual([]);
    expect(r.mxPath).toBeNull();
  });
  it("null MX", async () => {
    const r = await new LocalChecker(
      makeResolver({ [key("nomail.example", "MX")]: ["0 ."] }),
    ).check("jane@nomail.example");
    expect(r.failure).toBe("null_mx");
    expect(r.mxHosts).toEqual([]);
    expect(r.mxPath).toBeNull();
  });
});

describe("caching", () => {
  it("one lookup per domain", async () => {
    const calls: string[] = [];
    const checker = new LocalChecker(
      makeResolver({ [key("foo.com", "MX")]: ["10 mail.foo.com."] }, calls),
    );
    await checker.check("jane@foo.com");
    await checker.check("bob@foo.com");
    expect(calls).toEqual(["foo.com/MX"]);
  });
});
