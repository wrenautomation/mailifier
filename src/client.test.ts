/** The remote probe over a fake fetch: no network, no probe host. */
import { describe, expect, it } from "vitest";
import { RemoteProbe, RemoteProbeError } from "./client.js";
import type { FetchLike } from "./dns.js";

function client(payload: unknown, status = 200, seen?: { url: string; init?: RequestInit }[]) {
  const fetchImpl: FetchLike = async (url, init) => {
    seen?.push({ url, ...(init ? { init } : {}) });
    return new Response(JSON.stringify(payload), { status });
  };
  return new RemoteProbe("http://box:2525/", "tok-123", fetchImpl);
}

describe("RemoteProbe", () => {
  it("names itself for the handshake it stands in for", () =>
    expect(client({ result: "valid", raw: {} }).name).toBe("smtp"));

  it("posts the address with the bearer and hands back the verdict", async () => {
    const seen: { url: string; init?: RequestInit }[] = [];
    const verdict = await client(
      { result: "catch_all", raw: { reason: "catch_all" } },
      200,
      seen,
    ).verify("jane@foo.com");
    expect(verdict).toEqual({ result: "catch_all", raw: { reason: "catch_all" } });
    expect(seen[0]?.url).toBe("http://box:2525/verify");
    expect(seen[0]?.init?.body).toBe(JSON.stringify({ email: "jane@foo.com" }));
    expect(seen[0]?.init?.headers).toMatchObject({ authorization: "Bearer tok-123" });
  });

  it("carries the server's own short reason on an HTTP error", async () => {
    await expect(
      client({ error: "port 25 closed from this host" }, 503).verify("j@f.co"),
    ).rejects.toThrow(/503: port 25 closed/);
  });

  it("an answer that is not a verdict raises rather than guessing", async () => {
    await expect(client({ result: "maybe" }).verify("jane@foo.com")).rejects.toThrow(
      /unexpected verdict/,
    );
  });

  it("transport failure does not leak the token", async () => {
    const boom: FetchLike = async () => {
      throw new TypeError("fetch failed: Bearer tok-123 leaked?");
    };
    const err = await new RemoteProbe("http://box", "tok-123", boom)
      .verify("jane@foo.com")
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(RemoteProbeError);
    expect(String(err)).not.toContain("tok-123");
  });
});
