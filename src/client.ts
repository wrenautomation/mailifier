/**
 * A probe that asks another host: `POST /verify {email}` to a `makeProbeServer` running
 * somewhere port 25 is open, bearer-authenticated. The verdict is that host's own
 * SmtpProbe verdict, so an answer reads the same whichever machine ran the handshake.
 */

import type { FetchLike } from "./dns.js";
import { MAILBOX_RESULTS, type MailboxProbe, type MailboxResult, type Verdict } from "./verdict.js";

/** The far side did not answer, or answered with something other than a verdict: stop, do not guess. */
export class RemoteProbeError extends Error {
  override name = "RemoteProbeError";
}

export interface RemoteProbeSettings {
  /** Waits before each retry of a 429 "busy" (the server is at PROBE_MAX_IN_FLIGHT). */
  busyBackoffMs?: readonly number[];
  sleep?: (ms: number) => Promise<void>;
}

/** ~60s of waiting: a busy server frees a slot as soon as any probe in flight ends. */
const BUSY_BACKOFF_MS = [1_000, 2_000, 4_000, 8_000, 15_000, 30_000];

export class RemoteProbe implements MailboxProbe {
  readonly name = "smtp";
  private readonly base: string;
  private readonly busyBackoffMs: readonly number[];
  private readonly sleep: (ms: number) => Promise<void>;

  constructor(
    baseUrl: string,
    private readonly token: string,
    private readonly fetchImpl: FetchLike = fetch,
    settings: RemoteProbeSettings = {},
  ) {
    this.base = baseUrl.replace(/\/+$/, "");
    this.busyBackoffMs = settings.busyBackoffMs ?? BUSY_BACKOFF_MS;
    this.sleep = settings.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
  }

  /** Busy is backpressure, not failure: wait and ask again, and only then give up. */
  async verify(email: string): Promise<Verdict> {
    for (const wait of this.busyBackoffMs) {
      const verdict = await this.ask(email);
      if (verdict !== "busy") return verdict;
      await this.sleep(wait);
    }
    const verdict = await this.ask(email);
    if (verdict === "busy") throw new RemoteProbeError("probe host HTTP 429: busy");
    return verdict;
  }

  private async ask(email: string): Promise<Verdict | "busy"> {
    let resp: Response;
    try {
      resp = await this.fetchImpl(`${this.base}/verify`, {
        method: "POST",
        headers: { authorization: `Bearer ${this.token}`, "content-type": "application/json" },
        body: JSON.stringify({ email }),
        // A probe walks up to three MX hosts with a socket timeout each.
        signal: AbortSignal.timeout(60_000),
      });
    } catch (err) {
      // The token rides in a header, never in a message; keep the error to its name.
      throw new RemoteProbeError(
        `probe host unreachable: ${err instanceof Error ? err.name : "Error"}`,
      );
    }
    if (resp.status === 429) {
      await resp.body?.cancel();
      return "busy";
    }
    if (!resp.ok) {
      // The server's own error text (ours, short, never a secret); anything else is dropped.
      const detail = await resp
        .json()
        .then((d: unknown) =>
          d && typeof d === "object" ? (d as { error?: unknown }).error : null,
        )
        .catch(() => null);
      throw new RemoteProbeError(
        `probe host HTTP ${resp.status}${typeof detail === "string" ? `: ${detail}` : ""}`,
      );
    }
    const data = (await resp.json()) as { result?: unknown; raw?: unknown };
    if (!MAILBOX_RESULTS.includes(data.result as MailboxResult))
      throw new RemoteProbeError(`unexpected verdict: ${JSON.stringify(data.result)}`);
    return {
      result: data.result as MailboxResult,
      raw: (data.raw ?? {}) as Record<string, unknown>,
    };
  }
}
