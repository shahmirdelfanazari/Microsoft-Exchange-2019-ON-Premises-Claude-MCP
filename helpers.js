// Pure helpers shared by index.js (kept free of side effects so they can be unit tested).

// Escape a value for XML text or attribute content
export function xmlEscape(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&apos;");
}

// Escape a value for use inside an LDAP filter (RFC 4515)
export function ldapEscape(s) {
  return String(s).replace(/[\\*()\0]/g, c => "\\" + c.charCodeAt(0).toString(16).padStart(2, "0"));
}

// EWS reports most failures as HTTP 200 with ResponseClass="Error". Throw, so a tool never reports
// success for something Exchange refused.
export function assertEwsSuccess(resp, action) {
  if (!/ResponseClass="Error"/.test(resp)) return;
  const text = (resp.match(/<(?:[^:>]+:)?MessageText>([^<]+)</) || [])[1];
  const code = (resp.match(/<(?:[^:>]+:)?ResponseCode>([^<]+)</) || [])[1];
  throw new Error(`${action} failed: ${text || code || "Exchange returned an error"}${text && code ? ` (${code})` : ""}`);
}

// http(s)/ldap(s) URLs carry the service account's credentials: only the TLS schemes are accepted.
export function requireScheme(url, scheme, name) {
  if (!String(url).toLowerCase().startsWith(scheme + "://")) throw new Error(`${name} must start with ${scheme}:// (got ${String(url).split("://")[0]}://)`);
  return url;
}
