#!/usr/bin/env node
import { makeProbeServer } from "./server.js";
/**
 * Serve the probe on PROBE_PORT (2525). Env: PROBE_TOKEN (required), PROBE_HELO
 * (required), PROBE_HOST_GAP_MS, PROBE_MAX_IN_FLIGHT (calls at once, default 8),
 * PROBE_BIG_HOST_LANES (conversations at once with Google/Microsoft/Proofpoint/Mimecast
 * inbound hosts, default 1),
 * PROBE_CANARY_HOST (an MX known to answer; default Google's inbound).
 */
import { bigProviderLanes, dialTcp, SMTP_PORT, SmtpProbe } from "./smtp.js";

const port = Number(process.env.PROBE_PORT ?? 2525);
const token = process.env.PROBE_TOKEN ?? "";
const helo = process.env.PROBE_HELO ?? "";
if (!token || !helo) {
  console.error("PROBE_TOKEN and PROBE_HELO are required");
  process.exit(2);
}

const probe = new SmtpProbe({
  helo,
  perHostGapMs: Number(process.env.PROBE_HOST_GAP_MS ?? 1500),
  lanesFor: bigProviderLanes(Number(process.env.PROBE_BIG_HOST_LANES ?? 1)),
});
// One banner read from a well-known MX, remembered for ten minutes, says whether port
// 25 is open from here. Open once = trusted for the window; closed = checked again.
const canaryHost = process.env.PROBE_CANARY_HOST ?? "gmail-smtp-in.l.google.com";
const CANARY_TTL_MS = 10 * 60_000;
let canaryOpenUntil = 0;
async function port25Open(): Promise<boolean> {
  if (Date.now() < canaryOpenUntil) return true;
  try {
    const c = await dialTcp(canaryHost, SMTP_PORT, 8_000);
    try {
      const banner = await c.read();
      if (!banner.startsWith("220")) return false;
      await c.write("QUIT");
    } finally {
      c.close();
    }
    canaryOpenUntil = Date.now() + CANARY_TTL_MS;
    return true;
  } catch {
    return false;
  }
}

const server = makeProbeServer({
  probe,
  token,
  canary: port25Open,
  maxInFlight: Number(process.env.PROBE_MAX_IN_FLIGHT ?? 8),
  log: (line) => console.log(new Date().toISOString(), line),
});
server.listen(port, () => console.log(`mailifier listening on :${port} as ${helo}`));
for (const sig of ["SIGINT", "SIGTERM"] as const)
  process.once(sig, () => server.close(() => process.exit(0)));
