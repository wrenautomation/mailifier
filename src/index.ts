/**
 * mailifier: ask a mail server whether an address exists, without sending anything.
 *
 * Start at `verdict.ts` — `MailboxProbe` is the interface everything else implements,
 * and the one thing a caller should depend on.
 */
export * from "./address.js";
export * from "./client.js";
export * from "./dns.js";
export * from "./local.js";
export * from "./server.js";
export * from "./smtp.js";
export * from "./verdict.js";
