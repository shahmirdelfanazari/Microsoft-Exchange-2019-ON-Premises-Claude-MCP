import { test } from "node:test";
import assert from "node:assert/strict";
import { xmlEscape, ldapEscape, assertEwsSuccess, requireScheme, isWorkDay, isOpenDay, createPreviewStore } from "../helpers.js";

test("xmlEscape escapes markup and quotes", () => {
  assert.equal(xmlEscape(`a&b<c>"d'`), "a&amp;b&lt;c&gt;&quot;d&apos;");
  assert.equal(xmlEscape("ali@example.com"), "ali@example.com");
  assert.equal(xmlEscape("AAMkAG+/x=="), "AAMkAG+/x==");   // EWS item ids pass through unchanged
  assert.equal(xmlEscape(10), "10");
});

test("ldapEscape neutralises filter metacharacters (RFC 4515)", () => {
  assert.equal(ldapEscape("a*b(c)d\\e\0"), "a\\2ab\\28c\\29d\\5ce\\00");
  assert.equal(ldapEscape("x)(mail=*"), "x\\29\\28mail=\\2a");
  assert.equal(ldapEscape("ali@example.com"), "ali@example.com");
  assert.equal(ldapEscape("CN=Doe\\, John,OU=IT"), "CN=Doe\\5c, John,OU=IT");
});

test("assertEwsSuccess throws on ResponseClass=Error and passes success", () => {
  const okResp = `<m:CreateItemResponseMessage ResponseClass="Success"><m:ResponseCode>NoError</m:ResponseCode></m:CreateItemResponseMessage>`;
  assert.doesNotThrow(() => assertEwsSuccess(okResp, "Send"));
  const errResp = `<m:DeleteItemResponseMessage ResponseClass="Error"><m:MessageText>The specified object was not found in the store.</m:MessageText><m:ResponseCode>ErrorItemNotFound</m:ResponseCode></m:DeleteItemResponseMessage>`;
  assert.throws(() => assertEwsSuccess(errResp, "Delete"), /Delete failed: The specified object was not found in the store\. \(ErrorItemNotFound\)/);
  assert.throws(() => assertEwsSuccess(`<x ResponseClass="Error"/>`, "Update"), /Update failed: Exchange returned an error/);
});

test("requireScheme only accepts the TLS scheme", () => {
  assert.equal(requireScheme("https://mail.example.com/EWS/Exchange.asmx", "https", "EWS_URL"), "https://mail.example.com/EWS/Exchange.asmx");
  assert.throws(() => requireScheme("http://mail.example.com/EWS/Exchange.asmx", "https", "EWS_URL"), /EWS_URL must start with https:\/\//);
  assert.throws(() => requireScheme("ldap://dc1.example.com:389", "ldaps", "LDAP_URLS"), /LDAP_URLS must start with ldaps:\/\//);
});

test("work days follow the calendar date, not the server's timezone", () => {
  const day = s => new Date(s + "T00:00:00Z");
  // 2026-11-14 is a Saturday ... 2026-11-20 a Friday
  assert.deepEqual(["2026-11-14", "2026-11-15", "2026-11-16", "2026-11-17", "2026-11-18", "2026-11-19", "2026-11-20"].map(d => isWorkDay(day(d))),
    [true, true, true, true, true, false, false]);
  assert.equal(isOpenDay(day("2026-11-19")), true, "Thursday: open, not a working day");
  assert.equal(isOpenDay(day("2026-11-20")), false, "Friday: closed");
});

test("a preview can be used once, by the same user, for the same request, in the time window", () => {
  let clock = 0;
  const store = createPreviewStore({ ttlMs: 600000, minAgeMs: 2000, now: () => clock });
  const req = { to: ["sara@example.com"], subject: "Hi", body: "text" };
  assert.equal(store.consume("ali@example.com", "send_email", req), false, "nothing previewed yet");
  store.remember("ali@example.com", "send_email", req);
  assert.equal(store.consume("ali@example.com", "send_email", req), false, "too soon after the preview");
  clock = 3000;
  assert.equal(store.consume("eve@example.com", "send_email", req), false, "another user");
  assert.equal(store.consume("ali@example.com", "reply_email", req), false, "another tool");
  assert.equal(store.consume("ali@example.com", "send_email", { ...req, to: ["eve@example.com"] }), false, "changed recipient");
  assert.equal(store.consume("ALI@example.com", "send_email", { body: "text", subject: "Hi", to: ["sara@example.com"] }), true, "same request, other key order");
  assert.equal(store.consume("ali@example.com", "send_email", req), false, "single use");
  store.remember("ali@example.com", "send_email", req);
  clock += 600001;
  assert.equal(store.consume("ali@example.com", "send_email", req), false, "expired");
});
