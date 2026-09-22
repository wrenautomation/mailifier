/**
 * What an address is, before anyone dials a mail server: normalization, pragmatic
 * syntax rules, the freemail and role-account lists. Rules are pragmatic, not full
 * RFC 5321 — addresses that need quoting do not survive real business mail anyway.
 */

/** Providers where the domain identifies a person, not a business. Advisory, never a failure. */
export const FREEMAIL_DOMAINS: ReadonlySet<string> = new Set([
  "gmail.com",
  "googlemail.com",
  "yahoo.com",
  "yahoo.co.uk",
  "ymail.com",
  "aol.com",
  "outlook.com",
  "hotmail.com",
  "hotmail.co.uk",
  "live.com",
  "msn.com",
  "icloud.com",
  "me.com",
  "mac.com",
  "proton.me",
  "protonmail.com",
  "pm.me",
  "gmx.com",
  "gmx.net",
  "mail.com",
  "zoho.com",
  "yandex.com",
  "netscape.net",
  "juno.com",
  "netzero.net",
  // Consumer ISPs, national and regional.
  "att.net",
  "bellsouth.net",
  "centurylink.net",
  "centurytel.net",
  "charter.net",
  "comcast.net",
  "cox.net",
  "earthlink.net",
  "embarqmail.com",
  "frontier.com",
  "frontiernet.net",
  "gpcom.net",
  "hughes.net",
  "mchsi.com",
  "midconetwork.com",
  "optimum.net",
  "optonline.net",
  "ptd.net",
  "q.com",
  "roadrunner.com",
  "rr.com",
  "sbcglobal.net",
  "suddenlink.net",
  "twc.com",
  "verizon.net",
  "windstream.net",
  "wowway.com",
  "zoominternet.net",
]);

/** Functional mailboxes (info@, hello@): a role, not a person. Advisory, never a failure. */
export const ROLE_LOCALPARTS: ReadonlySet<string> = new Set([
  "abuse",
  "admin",
  "administrator",
  "billing",
  "contact",
  "help",
  "hello",
  "hr",
  "info",
  "jobs",
  "mail",
  "marketing",
  "no-reply",
  "noreply",
  "office",
  "postmaster",
  "privacy",
  "sales",
  "security",
  "support",
  "team",
  "webmaster",
]);

const LOCAL_RE = /^[a-z0-9!#$%&'*+/=?^_`{|}~.-]+$/;
const LABEL_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/;
// IDN labels arrive punycode-encoded ("xn--mnchen-3ya" = münchen).
const PUNYCODE_RE = /^xn--[a-z0-9-]+$/;

export function normalizeEmail(raw: string): string {
  let email = raw.trim().toLowerCase();
  if (email.startsWith("mailto:")) email = email.slice("mailto:".length);
  return email.replace(/^[<>]+|[<>]+$/g, "").trim();
}

/** Reason the (already normalized) address is undeliverable, or null. */
export function emailSyntaxError(email: string): string | null {
  const parts = email.split("@");
  if (parts.length !== 2) return "must contain exactly one @";
  const [local, domain] = parts as [string, string];
  if (!local) return "empty local part";
  if (local.length > 64) return "local part longer than 64 chars";
  if (email.length > 254) return "address longer than 254 chars";
  if (local.startsWith(".") || local.endsWith(".") || local.includes("..")) {
    return "misplaced dot in local part";
  }
  if (!LOCAL_RE.test(local)) return "illegal character in local part";
  if (!validDomain(domain)) return "invalid domain";
  return null;
}

export function validDomain(domain: string): boolean {
  if (!domain || domain.length > 253) return false;
  const labels = domain.replace(/\.+$/, "").split(".");
  if (labels.length < 2) return false;
  if (!labels.every((l) => LABEL_RE.test(l) || PUNYCODE_RE.test(l))) return false;
  const tld = labels[labels.length - 1] as string;
  return tld.length >= 2 && (/^[a-z]+$/.test(tld) || PUNYCODE_RE.test(tld));
}

export function emailDomain(email: string): string {
  return email.slice(email.lastIndexOf("@") + 1);
}

export function isFreemail(domain: string): boolean {
  return FREEMAIL_DOMAINS.has(domain.toLowerCase());
}

/** True for a functional mailbox by its local part alone; plus-tags stripped. A bare word is never an address. */
export function isRoleLocalpart(email: string): boolean {
  const at = email.indexOf("@");
  if (at < 0) return false;
  const local = email.slice(0, at).trim().toLowerCase();
  return ROLE_LOCALPARTS.has(local.split("+", 1)[0] as string);
}
