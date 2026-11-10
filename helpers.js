// Pure helpers shared by index.js (kept free of side effects so they can be unit tested).
import { createHash } from "crypto";

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

// 0=Sun ... 6=Sat. WORK_DAYS are the regular working days (Sat-Wed), used when looking for other
// days to suggest. OPEN_DAYS adds days the office is open but that are not working days (Thu):
// people can book them when they ask for that day, but they are not suggested.
export const WORK_DAYS = [6, 0, 1, 2, 3];
export const OPEN_DAYS = [...WORK_DAYS, 4];
// Both take a date at UTC midnight, as built from a YYYY-MM-DD calendar date, so the UTC weekday
// is that calendar date's weekday whatever the server's timezone.
export const isWorkDay = date => WORK_DAYS.includes(date.getUTCDay());
export const isOpenDay = date => OPEN_DAYS.includes(date.getUTCDay());

// Same request -> same text, whatever order the arguments came in
function canonical(v) {
  if (Array.isArray(v)) return v.map(canonical);
  if (v && typeof v === "object") return Object.fromEntries(Object.keys(v).sort().filter(k => v[k] !== undefined).map(k => [k, canonical(v[k])]));
  return v;
}

// Remembers which exact requests a user has been shown a preview of. A preview can be used once,
// no sooner than minAgeMs after it was shown (a duplicate fired together with the preview call does
// not count) and no later than ttlMs.
export function createPreviewStore({ ttlMs = 10 * 60 * 1000, minAgeMs = 2000, now = Date.now } = {}) {
  const shownAt = new Map();   // sha256(user, tool, arguments) -> time of the preview
  const keyOf = (user, tool, args) => createHash("sha256").update(JSON.stringify([String(user).toLowerCase(), tool, canonical(args)])).digest("hex");
  const sweep = time => { for (const [k, at] of shownAt) if (time - at > ttlMs) shownAt.delete(k); };
  return {
    remember(user, tool, args) {
      const time = now(); sweep(time);
      const k = keyOf(user, tool, args);
      if (!shownAt.has(k)) shownAt.set(k, time);
    },
    consume(user, tool, args) {
      const time = now(); sweep(time);
      const k = keyOf(user, tool, args);
      const at = shownAt.get(k);
      if (at === undefined || time - at < minAgeMs) return false;
      shownAt.delete(k);
      return true;
    },
  };
}
