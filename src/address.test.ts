/** The rules that decide an address is hopeless before anything is dialled. */
import { describe, expect, it } from "vitest";
import {
  emailDomain,
  emailSyntaxError,
  isFreemail,
  isRoleLocalpart,
  normalizeEmail,
} from "./address.js";

describe("normalizeEmail", () => {
  it.each([
    ["  Jane@Foo.Com ", "jane@foo.com"],
    ["mailto:jane@foo.com", "jane@foo.com"],
    ["<jane@foo.com>", "jane@foo.com"],
  ])("%s -> %s", (raw, want) => expect(normalizeEmail(raw)).toBe(want));
});

describe("emailSyntaxError", () => {
  it("passes an ordinary address", () => expect(emailSyntaxError("jane@foo.com")).toBeNull());
  it.each([
    ["jane", "must contain exactly one @"],
    ["@foo.com", "empty local part"],
    [".jane@foo.com", "misplaced dot in local part"],
    ["ja ne@foo.com", "illegal character in local part"],
    ["jane@foo", "invalid domain"],
  ])("%s -> %s", (email, reason) => expect(emailSyntaxError(email)).toBe(reason));
});

describe("flags", () => {
  it("domain, freemail, role", () => {
    expect(emailDomain("jane@foo.com")).toBe("foo.com");
    expect(isFreemail("gmail.com")).toBe(true);
    expect(isFreemail("foo.com")).toBe(false);
    expect(isRoleLocalpart("info@foo.com")).toBe(true);
    expect(isRoleLocalpart("info+tag@foo.com")).toBe(true);
    expect(isRoleLocalpart("jane@foo.com")).toBe(false);
  });
});
