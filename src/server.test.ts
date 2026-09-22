import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { makeProbeServer } from "./server.js";
import type { MailboxProbe } from "./verdict.js";

const probe: MailboxProbe = {
  name: "stub",
  async verify(email) {
    return { result: email.startsWith("bad") ? "invalid" : "valid", raw: { reason: "stub" } };
  },
};
const server = makeProbeServer({ probe, token: "secret-token" });
let base = "";
beforeAll(async () => {
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => new Promise<void>((r) => server.close(() => r())));

const post = (body: unknown, token = "secret-token") =>
  fetch(`${base}/verify`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify(body),
  });

describe("probe server", () => {
  it("answers health without a token", async () => {
    const r = await fetch(`${base}/healthz`);
    expect(r.status).toBe(200);
    expect(await r.json()).toMatchObject({ ok: true });
  });
  it("refuses a wrong or missing bearer", async () => {
    expect((await post({ email: "a@b.co" }, "nope")).status).toBe(401);
    expect((await fetch(`${base}/verify`, { method: "POST" })).status).toBe(401);
  });
  it("hands back the verifier's verdict", async () => {
    const r = await post({ email: "bad@b.co" });
    expect(r.status).toBe(200);
    expect(await r.json()).toEqual({ result: "invalid", raw: { reason: "stub" } });
  });
  it("rejects a malformed address before probing", async () => {
    expect((await post({ email: "not an email" })).status).toBe(400);
    expect((await post({})).status).toBe(400);
  });
  it("404s anything else", async () => {
    expect((await fetch(`${base}/other`)).status).toBe(404);
  });

  it("with a closed port 25 the canary answers 503 and never a verdict", async () => {
    let open = false;
    const canaried = makeProbeServer({ probe, token: "secret-token", canary: async () => open });
    await new Promise<void>((r) => canaried.listen(0, "127.0.0.1", () => r()));
    const url = `http://127.0.0.1:${(canaried.address() as AddressInfo).port}`;
    try {
      const call = () =>
        fetch(`${url}/verify`, {
          method: "POST",
          headers: { authorization: "Bearer secret-token", "content-type": "application/json" },
          body: JSON.stringify({ email: "a@b.co" }),
        });
      const closed = await call();
      expect(closed.status).toBe(503);
      expect(await closed.json()).toEqual({ error: "port 25 closed from this host" });
      expect(await (await fetch(`${url}/healthz`)).json()).toMatchObject({ port_25: false });
      open = true;
      expect((await call()).status).toBe(200);
    } finally {
      await new Promise<void>((r) => canaried.close(() => r()));
    }
  });
});
