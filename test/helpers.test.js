import { test } from "node:test";
import assert from "node:assert/strict";
import { xmlEscape, ldapEscape, assertEwsSuccess, requireScheme } from "../helpers.js";

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
