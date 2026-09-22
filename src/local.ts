/**
 * Stage 1: everything knowable without dialling anyone, run before a probe opens a
 * socket. Cheap, and it catches most of what a paid service would charge for.
 *
 * Failures are definitive (an `invalid` nobody needs to confirm): broken syntax, known
 * typosquat domains, disposable providers, domains with no mail routing. Flags are
 * advisory: role accounts and freemail are common for SMBs; the caller decides what to do with them.
 * A DNS lookup that errors, or that the resolver couldn't answer authoritatively
 * (SERVFAIL/REFUSED), flags mx_unresolved and passes: only an authoritative empty
 * answer may mean "no mail routing".
 */
import { emailDomain, emailSyntaxError, isFreemail, isRoleLocalpart } from "./address.js";
import { DohError, type Resolver, resolve } from "./dns.js";

/** Registered typosquats of the big providers: mail often ACCEPTS there, so "deliverable" is the wrong signal. */
export const TYPO_DOMAINS: ReadonlySet<string> = new Set([
  "gmial.com",
  "gmal.com",
  "gamil.com",
  "gmai.com",
  "gmil.com",
  "gnail.com",
  "gmaill.com",
  "hotmial.com",
  "hotmal.com",
  "hotnail.com",
  "yahooo.com",
  "yaho.com",
  "outlok.com",
]);
export const DISPOSABLE_DOMAINS: ReadonlySet<string> = new Set([
  "mailinator.com",
  "guerrillamail.com",
  "sharklasers.com",
  "10minutemail.com",
  "temp-mail.org",
  "tempmail.com",
  "yopmail.com",
  "throwawaymail.com",
  "getnada.com",
  "maildrop.cc",
  "trashmail.com",
  "dispostable.com",
  "fakeinbox.com",
]);

export type MxPath = "mx" | "a" | "aaaa";
export type LocalFlag = "role_account" | "freemail" | "mx_fallback" | "mx_unresolved";

export interface LocalCheck {
  email: string;
  /** null = passed stage 1 */
  failure: string | null;
  flags: readonly LocalFlag[];
  /** Resolved MX hosts (lowercased, priority-stripped); empty whenever no real MX was found. */
  mxHosts: readonly string[];
  /** Which record type supplied deliverability. */
  mxPath: MxPath | null;
  passed: boolean;
}

interface MxStatus {
  failure: string | null;
  flags: readonly LocalFlag[];
  hosts: readonly string[];
  path: MxPath | null;
}

const check = (
  email: string,
  failure: string | null,
  flags: readonly LocalFlag[] = [],
  mxHosts: readonly string[] = [],
  mxPath: MxPath | null = null,
): LocalCheck => ({ email, failure, flags, mxHosts, mxPath, passed: failure === null });

export interface LocalCheckerLike {
  check(email: string): Promise<LocalCheck>;
}

/** Checks one email at a time; MX lookups are cached per domain, since imports cluster on shared domains. */
export class LocalChecker implements LocalCheckerLike {
  private readonly cache = new Map<string, Promise<MxStatus>>();
  constructor(private readonly resolver: Resolver = (n, t) => resolve(n, t)) {}

  async check(email: string): Promise<LocalCheck> {
    const reason = emailSyntaxError(email);
    if (reason) return check(email, `syntax: ${reason}`);
    const domain = emailDomain(email);
    if (TYPO_DOMAINS.has(domain)) return check(email, "typo_domain");
    if (DISPOSABLE_DOMAINS.has(domain)) return check(email, "disposable_domain");
    const flags: LocalFlag[] = [];
    if (isRoleLocalpart(email)) flags.push("role_account");
    if (isFreemail(domain)) flags.push("freemail");
    const mx = await this.mxStatus(domain);
    return check(email, mx.failure, [...flags, ...mx.flags], mx.hosts, mx.path);
  }

  private mxStatus(domain: string): Promise<MxStatus> {
    let status = this.cache.get(domain);
    if (!status) {
      status = this.lookup(domain);
      this.cache.set(domain, status);
    }
    return status;
  }

  private async lookup(domain: string): Promise<MxStatus> {
    let records: string[];
    try {
      records = await this.resolver(domain, "MX");
    } catch (err) {
      // A resolver hiccup is not evidence of anything about the domain: fail open.
      if (err instanceof DohError)
        return { failure: null, flags: ["mx_unresolved"], hosts: [], path: null };
      throw err;
    }
    // RFC 7505 null MX: "0 ." declares the domain never receives mail.
    const targets = records
      .map((r) => r.trim().split(/\s+/).at(-1) ?? "")
      .filter((_, i) => records[i]?.trim());
    if (targets.length && targets.every((t) => t === "." || t === ""))
      return { failure: "null_mx", flags: [], hosts: [], path: null };
    if (targets.length) {
      const hosts = [
        ...new Set(targets.map((t) => t.replace(/\.+$/, "").toLowerCase()).filter(Boolean)),
      ].sort();
      return { failure: null, flags: [], hosts, path: "mx" };
    }
    // No MX: mail falls back to the domain's own address record, A then AAAA (RFC 5321 §5.1).
    // Real routing but a weaker signal, so flagged; only a domain with none of MX/A/AAAA is undeliverable.
    try {
      if ((await this.resolver(domain, "A")).length)
        return { failure: null, flags: ["mx_fallback"], hosts: [], path: "a" };
      if ((await this.resolver(domain, "AAAA")).length)
        return { failure: null, flags: ["mx_fallback"], hosts: [], path: "aaaa" };
    } catch (err) {
      if (err instanceof DohError)
        return { failure: null, flags: ["mx_unresolved"], hosts: [], path: null };
      throw err;
    }
    return { failure: "no_mx", flags: [], hosts: [], path: null };
  }
}
