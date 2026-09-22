/**
 * The probe as a service: `POST /verify {email}` → a verdict, run on a host that can
 * open port 25. Bearer-authenticated; one process, one probe, so the per-MX gap holds
 * across every caller. `GET /healthz` for the box's own checks. Nothing here sends
 * mail: no DATA, no delivery, ever.
 *
 * The canary: before a verdict the server asks whether port 25 is open from here at
 * all (most clouds close it until asked). Closed means 503, never a `risky` verdict
 * per address: that is this host's problem, not the mailbox's.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { emailSyntaxError } from "./address.js";
import type { MailboxProbe } from "./verdict.js";

export interface ProbeServerOptions {
  probe: MailboxProbe;
  token: string;
  /** Calls at once across all MX hosts; the probe still serialises per host. */
  maxInFlight?: number;
  /** Can this host open port 25 right now? Absent = assume yes. */
  canary?: () => Promise<boolean>;
  log?: (line: string) => void;
}

const MAX_BODY = 4_096;

export function makeProbeServer(opts: ProbeServerOptions): Server {
  const maxInFlight = opts.maxInFlight ?? 8;
  const log = opts.log ?? (() => {});
  let inFlight = 0;
  return createServer(async (req, res) => {
    try {
      if (req.method === "GET" && req.url === "/healthz") {
        const port25 = opts.canary ? await opts.canary() : null;
        return json(res, 200, { ok: true, in_flight: inFlight, port_25: port25 });
      }
      if (req.method !== "POST" || req.url !== "/verify") return json(res, 404, { error: "no" });
      const offered = (req.headers.authorization ?? "").replace(/^Bearer\s+/i, "");
      if (!timingSafeEqual(offered, opts.token)) return json(res, 401, { error: "no" });
      if (inFlight >= maxInFlight) return json(res, 429, { error: "busy" });
      const body = await readJson(req);
      const email = typeof body.email === "string" ? body.email.trim() : "";
      const syntax = email ? emailSyntaxError(email) : "missing email";
      if (syntax) return json(res, 400, { error: syntax });
      if (opts.canary && !(await opts.canary())) {
        log("port 25 closed from this host");
        return json(res, 503, { error: "port 25 closed from this host" });
      }
      inFlight += 1;
      try {
        const t0 = Date.now();
        const verdict = await opts.probe.verify(email);
        log(`${verdict.result} ${String(verdict.raw.reason ?? "")} ${Date.now() - t0}ms`);
        return json(res, 200, verdict);
      } finally {
        inFlight -= 1;
      }
    } catch (err) {
      log(`error ${err instanceof Error ? err.name : "Error"}`);
      return json(res, 500, { error: err instanceof Error ? err.name : "error" });
    }
  });
}

function json(res: ServerResponse, status: number, payload: unknown): void {
  const text = JSON.stringify(payload);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(text),
  });
  res.end(text);
}

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  let text = "";
  for await (const chunk of req) {
    text += chunk;
    if (text.length > MAX_BODY) throw new Error("body too large");
  }
  try {
    const parsed: unknown = JSON.parse(text || "{}");
    return parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

/** Compare the whole string every time; no early exit on a wrong prefix. */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length || b.length === 0) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
