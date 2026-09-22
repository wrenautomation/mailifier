/**
 * What a mailbox check can say, and the one interface every way of asking implements.
 *
 * Four answers, and the honest thing is that only two of them are facts:
 *   valid      the mail server accepted the address; that server says the mailbox is there
 *   invalid    the mail server refused it by name ("no such user"), or the domain takes no mail
 *   catch_all  the domain accepts everything, so acceptance says nothing about this address
 *   risky      nobody would tell us: greylisting, a refused connection, a policy block
 *
 * `raw` is the evidence behind the answer (which MX, which reply code, the transcript),
 * kept so a verdict can be argued with later. It never holds a credential.
 */
export const MAILBOX_RESULTS = ["valid", "invalid", "risky", "catch_all"] as const;
export type MailboxResult = (typeof MAILBOX_RESULTS)[number];

export interface Verdict {
  result: MailboxResult;
  raw: Record<string, unknown>;
}

/**
 * A way of asking whether a mailbox exists. `SmtpProbe` dials the mail server itself;
 * `RemoteProbe` asks another host that can. Callers depend on this, not on either one.
 *
 * Deliberately not here: whether a verdict may be trusted, and whether it costs money.
 * Those are the caller's policy about a probe, not something a probe knows about itself.
 */
export interface MailboxProbe {
  readonly name: string;
  verify(email: string): Promise<Verdict>;
}
