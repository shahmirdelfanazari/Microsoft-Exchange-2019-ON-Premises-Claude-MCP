import { writeFileSync, readdirSync, unlinkSync } from 'fs';
import * as jose from "jose";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import { createServer } from "http";
import { randomUUID } from "crypto";
import { rootCertificates } from "tls";
import httpntlm from "httpntlm";
import {
  MAIL_DOMAIN, EWS_URL, EWS_CA, EWS_TLS_INSECURE, SVC_USERNAME, SVC_PASSWORD, LDAP_BIND_UPN, LDAP_BIND_PASSWORD,
  OIDC_ISSUER, OIDC_JWKS_URL, OIDC_AUTH_BASE, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET,
  OIDC_ALLOWED_CLIENTS, OIDC_REQUIRE_EMAIL_VERIFIED, OIDC_AUDIENCE, LEGACY_TOKEN_ARG,
  MAX_SESSIONS, MAX_SESSIONS_PER_USER,
  PUBLIC_URL, PORT, LDAP_URLS, LDAP_BASE_DN, LDAPS_CA,
  ROOMS, RESTRICTED_ROOMS, EXCLUDED_ROOMS, ROOM_SIZE_GUIDE
} from "./config.js";
import { T } from "./i18n.js";
import { xmlEscape, ldapEscape, assertEwsSuccess, isWorkDay, isOpenDay, createPreviewStore } from "./helpers.js";

// ─── Iran Timezone Helpers ───────────────────────────────────────────────────
function nowIran()
 {
  // Iran is UTC+3:30
  const now = new Date();
  now.setMinutes(now.getMinutes() + 210);
  return now;
}

function todayIran() {
  const now = nowIran();
  const pad = n => String(n).padStart(2, "0");
  return `${now.getUTCFullYear()}-${pad(now.getUTCMonth()+1)}-${pad(now.getUTCDate())}`;
}

function iranTimeString() {
  const now = nowIran();
  const pad = n => String(n).padStart(2, "0");
  return `${pad(now.getUTCHours())}:${pad(now.getUTCMinutes())}`;
}

function isPastDateTime(iranLocalISO) {
  const [datePart, timePart] = iranLocalISO.replace('Z','').split('T');
  const [year, month, day] = datePart.split('-').map(Number);
  const [hour, minute] = (timePart || '00:00').split(':').map(Number);
  const utcMs = Date.UTC(year, month-1, day, hour, minute) - (210 * 60 * 1000);
  return utcMs < Date.now();
}

// ─── Persian Name Fuzzy Match ────────────────────────────────────────────────
// ─── Preview helper: date + weekday + relation to today ──────────────────────
// The date is resolved server-side so a stale or assumed date is visible to the
// user in the preview BEFORE any invitation is sent.
function describeDate(dateStr) {
  const days = T.weekdays;
  const [y, mo, dd] = dateStr.split('-').map(Number);
  const target = Date.UTC(y, mo - 1, dd);
  const dow = new Date(target).getUTCDay();
  const [ty, tmo, tdd] = todayIran().split('-').map(Number);
  const diff = Math.round((target - Date.UTC(ty, tmo - 1, tdd)) / 86400000);
  let rel;
  if (diff === 0) rel = T.today;
  else if (diff === 1) rel = T.tomorrow;
  else if (diff === -1) rel = T.yesterday + ' \u26a0\ufe0f';
  else if (diff > 1) rel = T.inDays(diff);
  else rel = T.daysAgo(Math.abs(diff)) + ' \u26a0\ufe0f';
  return days[dow] + ' ' + dateStr + ' (' + rel + ')';
}

function normalizePersianName(name) {
  if (!name) return '';
  return name
    .replace(/\s+/g, '') // remove all spaces
    .replace(/\u064a/g, '\u06cc')  // normalize Arabic ya to Persian ya
    .replace(/\u0643/g, '\u06a9')  // normalize Arabic kaf to Persian kaf
    .replace(/\u0629/g, '\u0647')  // normalize ta marbuta
    .replace(/\u0623|\u0625|\u0622/g, '\u0627') // normalize alef variants
    .toLowerCase();
}

function persianNameScore(query, candidate) {
  const q = normalizePersianName(query);
  const c = normalizePersianName(candidate);
  if (c === q) return 100;
  if (c.includes(q) || q.includes(c)) return 90;
  // Check all words of query appear in candidate (in any order)
  const qWords = query.trim().split(/\s+/).map(normalizePersianName);
  const cWords = candidate.trim().split(/\s+/).map(normalizePersianName);
  const allFound = qWords.every(qw => cWords.some(cw => cw.includes(qw) || qw.includes(cw)));
  if (allFound) return 80;
  // Partial word matches
  const matchCount = qWords.filter(qw => c.includes(qw) || qw.length > 2 && c.includes(qw.substring(0,3))).length;
  return Math.round((matchCount / qWords.length) * 60);
}

// ─── OIDC (Keycloak) JWT Validation ───────────────────────────────────────────
const _jwks = jose.createRemoteJWKSet(new URL(OIDC_JWKS_URL));

async function validateJWT(token) {
  if (!token) return null;
  try {
    const { payload } = await jose.jwtVerify(token, _jwks, { issuer: OIDC_ISSUER, ...(OIDC_AUDIENCE ? { audience: OIDC_AUDIENCE } : {}) });
    // Only accept access tokens issued to this app: a token another client in the realm
    // obtained (azp/aud) must not open mailboxes here.
    const aud = Array.isArray(payload.aud) ? payload.aud : payload.aud ? [payload.aud] : [];
    if (!OIDC_ALLOWED_CLIENTS.includes(payload.azp) && !aud.some(a => OIDC_ALLOWED_CLIENTS.includes(a))) return null;
    if (payload.typ && payload.typ !== "Bearer") return null;
    if (!payload.email || (OIDC_REQUIRE_EMAIL_VERIFIED && payload.email_verified !== true)) return null;
    return payload;
  } catch {
    return null;
  }
}

const SLOT_DURATION_MIN = 60;
const WORK_START_HOUR = 9;
const WORK_END_HOUR = 22;

// ─── Auxiliary HTTP server (OAuth callback, attachment downloads) ─────────────
import { registerDownload } from "./login-server.js";
import ldapjsPkg from "ldapjs";

// ── LDAP helpers for org chart ──

const LDAP_SERVERS = LDAP_URLS;

function ldapAttr(entry, name) {
  const a = entry.attributes.find(a => a.type.toLowerCase() === name.toLowerCase());
  if (!a) return null;
  return a.values.length === 1 ? a.values[0] : a.values;
}

function ldapSearch(client, baseDN, filter, attributes) {
  return new Promise((resolve, reject) => {
    client.search(baseDN, { filter, scope: 'sub', attributes }, (err, res) => {
      if (err) return reject(err);
      const entries = [];
      res.on('searchEntry', (e) => entries.push(e));
      res.on('searchReference', () => {});
      res.on('error', (e) => { if (e.name === 'ReferralError') resolve(entries); else reject(e); });
      res.on('end', () => resolve(entries));
    });
  });
}

async function getLdapClient() {
  for (const url of LDAP_SERVERS) {
    const client = await new Promise((resolve) => {
      const c = ldapCreateClient({ url, timeout: 5000, connectTimeout: 5000, tlsOptions: { ca: LDAPS_CA, rejectUnauthorized: true } });
      c.on('error', () => resolve(null));
      c.bind(LDAP_BIND_UPN, LDAP_BIND_PASSWORD, (err) => {
        if (err) { c.destroy(); resolve(null); } else resolve(c);
      });
    });
    if (client) return client;
  }
  return null;
}

async function ldapGetDirectReports(managerEmail) {
  const client = await getLdapClient();
  if (!client) throw new Error('All LDAP servers unreachable');
  try {
    const mgr = await ldapSearch(client, LDAP_BASE_DN, `(mail=${ldapEscape(managerEmail)})`, ['distinguishedName','displayName']);
    if (!mgr.length) return null;
    const managerDN = ldapAttr(mgr[0], 'distinguishedName');
    const managerName = ldapAttr(mgr[0], 'displayName');
    const reports = await ldapSearch(client, LDAP_BASE_DN,
      `(&(objectClass=user)(manager=${ldapEscape(managerDN)})(mail=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))`,
      ['displayName','mail']
    );
    return {
      managerName,
      members: reports.map(e => ({ name: ldapAttr(e,'displayName'), email: ldapAttr(e,'mail') })).filter(m => m.email)
    };
  } finally {
    try { client.unbind(); } catch(e) {}
  }
}


const { createClient: ldapCreateClient } = ldapjsPkg;
const mcpTransports = new Map();

// ─── NTLM EWS ─────────────────────────────────────────────────────────────────
function ewsRequest(username, password, body, impersonateEmail = null) {
  const actualUser = impersonateEmail ? SVC_USERNAME : username;
  const actualPass = impersonateEmail ? SVC_PASSWORD : password;
  const finalBody = impersonateEmail
    ? body.replace(/<soap:Body>/, `<soap:Header><t:ExchangeImpersonation><t:ConnectingSID><t:PrimarySmtpAddress>${xmlEscape(impersonateEmail)}</t:PrimarySmtpAddress></t:ConnectingSID></t:ExchangeImpersonation></soap:Header><soap:Body>`)
    : body;
  return new Promise((resolve, reject) => {
    httpntlm.post({
      url: EWS_URL, username: actualUser, password: actualPass, workstation: "", domain: "",
      body: finalBody,
      headers: { "Content-Type": "text/xml; charset=utf-8", "Accept": "text/xml" },
      rejectUnauthorized: !EWS_TLS_INSECURE,
      ...(EWS_CA ? { ca: [...rootCertificates, EWS_CA] } : {})
    }, (err, res) => {
      if (err) return reject(err);
      if (res.statusCode === 401) return reject(new Error("AUTH_FAILED"));
      if (res.statusCode < 200 || res.statusCode >= 300) return reject(new Error(`EWS error: ${res.statusCode}\n${res.body}`));
      resolve(res.body);
    });
  });
}

// ─── EWS: Resolve Names ───────────────────────────────────────────────────────
async function resolveNames(query) {
  // Build multiple query variants for Persian fuzzy matching
  const queries = new Set([query]);
  // Add space-removed variant
  queries.add(query.replace(/\s+/g, ''));
  // Add first word only and last word only
  const words = query.trim().split(/\s+/);
  if (words.length > 1) {
    queries.add(words[0]);
    queries.add(words[words.length - 1]);
    // Add first+last (skip middle)
    if (words.length > 2) queries.add(words[0] + ' ' + words[words.length-1]);
  }

  const allResults = new Map(); // email -> {email, name, score}

  for (const q of queries) {
    const xml = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Body>
    <m:ResolveNames ReturnFullContactData="true" SearchScope="ActiveDirectory">
      <m:UnresolvedEntry>${xmlEscape(q)}</m:UnresolvedEntry>
    </m:ResolveNames>
  </soap:Body>
</soap:Envelope>`;
    try {
      const response = await ewsRequest(SVC_USERNAME, SVC_PASSWORD, xml);
      const regex = /<(?:[^:>]+:)?Resolution>([\s\S]*?)<\/(?:[^:>]+:)?Resolution>/g;
      let match;
      while ((match = regex.exec(response)) !== null) {
        const block = match[1];
        const email = (block.match(/<(?:[^:>]+:)?EmailAddress>([^<]+)</) || [])[1];
        const name = (block.match(/<(?:[^:>]+:)?DisplayName>([^<]+)</) || [])[1];
        const type = (block.match(/<(?:[^:>]+:)?MailboxType>([^<]+)</) || [])[1];
        if (email && type !== "PublicDL") {
          const score = persianNameScore(query, name || email);
          if (!allResults.has(email) || allResults.get(email).score < score) {
            allResults.set(email, { email, name: name || email, score });
          }
        }
      }
    } catch(e) {}
  }

  // Sort by score descending, keep score for filtering
  return Array.from(allResults.values())
    .sort((a, b) => b.score - a.score);
}

// ─── EWS: Get Rooms ───────────────────────────────────────────────────────────
async function getRoomLists() {
  const xml = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Body>
    <m:GetRoomLists/>
  </soap:Body>
</soap:Envelope>`;
  const response = await ewsRequest(SVC_USERNAME, SVC_PASSWORD, xml);
  const lists = [];
  const regex = /<(?:[^:>]+:)?Address>([\s\S]*?)<\/(?:[^:>]+:)?Address>/g;
  let match;
  while ((match = regex.exec(response)) !== null) {
    const block = match[1];
    const email = (block.match(/<(?:[^:>]+:)?EmailAddress>([^<]+)</) || [])[1];
    const name = (block.match(/<(?:[^:>]+:)?Name>([^<]+)</) || [])[1];
    if (email) lists.push({ email, name: name || email });
  }
  return lists;
}

async function getRoomsInList(listEmail) {
  const xml = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Body>
    <m:GetRooms>
      <m:RoomList><t:EmailAddress>${xmlEscape(listEmail)}</t:EmailAddress></m:RoomList>
    </m:GetRooms>
  </soap:Body>
</soap:Envelope>`;
  const response = await ewsRequest(SVC_USERNAME, SVC_PASSWORD, xml);
  const rooms = [];
  const regex = /<(?:[^:>]+:)?Room>([\s\S]*?)<\/(?:[^:>]+:)?Room>/g;
  let match;
  while ((match = regex.exec(response)) !== null) {
    const block = match[1];
    const email = (block.match(/<(?:[^:>]+:)?EmailAddress>([^<]+)</) || [])[1];
    const name = (block.match(/<(?:[^:>]+:)?Name>([^<]+)</) || [])[1];
    if (email) rooms.push({ email, name: name || email });
  }
  return rooms;
}

async function getRooms() {
  try {
    const lists = await getRoomLists();
    const allRooms = [];
    for (const list of lists) {
      const rooms = await getRoomsInList( list.email);
      rooms.forEach(r => allRooms.push({ ...r, list: list.name }));
    }
    if (allRooms.length > 0) return allRooms;
  } catch {}

  // Fallback room list from rooms.json
  return ROOMS.map(r => ({ ...r, restricted: !!RESTRICTED_ROOMS[r.email] }));
}

// ─── Room display name lookup ─────────────────────────────────────────────────
const ROOM_NAMES = Object.fromEntries(ROOMS.map(r => [r.email, r.name]));
function getRoomDisplayName(email) {
  return ROOM_NAMES[email] || email;
}

function isValidRoomEmail(email) {
  if (!email) return true; // no room is ok
  // Must match known room email pattern
  return Object.keys(ROOM_NAMES).includes(email.toLowerCase()) ||
         !email.includes('room-'); // non-room emails are attendees, not rooms
}

function validateRoomEmail(roomEmail) {
  if (!roomEmail) return null;
  const lower = roomEmail.toLowerCase();
  // Check if it's a known room email exactly
  if (ROOM_NAMES[lower]) return lower;
  // Not in ROOM_NAMES — try to find by partial match
  const keys = Object.keys(ROOM_NAMES);
  // e.g. "a1@example.com" -> match "room-a1@example.com"
  const match = keys.find(k => {
    const shortName = k.replace('room-','').split('@')[0]; // e.g. "a1"
    const inputName = lower.split('@')[0]; // e.g. "a1"
    return shortName === inputName || k === lower || k.includes(inputName);
  });
  if (match) return match; // auto-correct to valid email
  // In our own domain but not in our list — invalid room
  if (lower.endsWith('@' + MAIL_DOMAIN)) return null;
  return roomEmail; // external email, pass through
}

// ─── EWS: Get Availability ────────────────────────────────────────────────────
async function getAvailability(emails, startDate, endDate) {
  const attendees = emails.map(e =>
    `<t:MailboxData><t:Email><t:Address>${xmlEscape(e)}</t:Address></t:Email><t:AttendeeType>Required</t:AttendeeType></t:MailboxData>`
  ).join("");

  const xml = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Body>
    <m:GetUserAvailabilityRequest>
      <t:TimeZone>
        <t:Bias>-210</t:Bias>
        <t:StandardTime><t:Bias>0</t:Bias><t:Time>02:00:00</t:Time><t:DayOrder>1</t:DayOrder><t:Month>10</t:Month><t:DayOfWeek>Sunday</t:DayOfWeek></t:StandardTime>
        <t:DaylightTime><t:Bias>0</t:Bias><t:Time>02:00:00</t:Time><t:DayOrder>1</t:DayOrder><t:Month>4</t:Month><t:DayOfWeek>Sunday</t:DayOfWeek></t:DaylightTime>
      </t:TimeZone>
      <m:MailboxDataArray>${attendees}</m:MailboxDataArray>
      <t:FreeBusyViewOptions>
        <t:TimeWindow>
          <t:StartTime>${xmlEscape(startDate)}</t:StartTime>
          <t:EndTime>${xmlEscape(endDate)}</t:EndTime>
        </t:TimeWindow>
        <t:MergedFreeBusyIntervalInMinutes>30</t:MergedFreeBusyIntervalInMinutes>
        <t:RequestedView>DetailedMerged</t:RequestedView>
      </t:FreeBusyViewOptions>
    </m:GetUserAvailabilityRequest>
  </soap:Body>
</soap:Envelope>`;

  const response = await ewsRequest(SVC_USERNAME, SVC_PASSWORD, xml);

  // Parse busy times per mailbox. Walk one <FreeBusyResponse> per requested mailbox (same order as the
  // request) so a mailbox Exchange cannot resolve (e.g. a mistyped address) cannot shift the others' data.
  const parseEvents = (block) => {
    const busySlots = [];
    const eventRegex = /<(?:[^:>]+:)?CalendarEvent>([\s\S]*?)<\/(?:[^:>]+:)?CalendarEvent>/g;
    let em;
    while ((em = eventRegex.exec(block)) !== null) {
      const ev = em[1];
      const start = (ev.match(/<(?:[^:>]+:)?StartTime>([^<]+)</) || [])[1];
      const end = (ev.match(/<(?:[^:>]+:)?EndTime>([^<]+)</) || [])[1];
      const status = (ev.match(/<(?:[^:>]+:)?BusyType>([^<]+)</) || [])[1];
      if (start && end && status !== "Free") busySlots.push({ start, end, status });
    }
    return busySlots;
  };
  const results = {};
  const errors = [];
  const respBlocks = [...response.matchAll(/<(?:[^:>]+:)?FreeBusyResponse>([\s\S]*?)<\/(?:[^:>]+:)?FreeBusyResponse>/g)].map(m => m[1]);
  if (respBlocks.length === emails.length) {
    respBlocks.forEach((block, i) => {
      const cls = (block.match(/ResponseClass="([^"]+)"/) || [])[1];
      if (cls === "Error") errors.push(emails[i]);
      results[emails[i]] = cls === "Error" ? [] : parseEvents(block);
    });
  } else {
    // Unexpected response shape — fall back to the previous positional FreeBusyView parsing
    const views = [...response.matchAll(/<(?:[^:>]+:)?FreeBusyView>([\s\S]*?)<\/(?:[^:>]+:)?FreeBusyView>/g)].map(m => m[1]);
    views.forEach((block, i) => { if (i < emails.length) results[emails[i]] = parseEvents(block); });
  }
  // Addresses Exchange could not resolve. Non-enumerable, so Object.keys(results) is unchanged for all callers.
  Object.defineProperty(results, "__errors", { value: errors, enumerable: false });
  return results;
}

// ─── Helpers: Find free slots ─────────────────────────────────────────────────

function generateSlots(dateStr) {
  const slots = [];
  const [year, month, day] = dateStr.split('-').map(Number);
  const date = new Date(Date.UTC(year, month-1, day));
  if (!isOpenDay(date)) return slots;
  const pad = n => String(n).padStart(2, "0");
  for (let h = WORK_START_HOUR; h < WORK_END_HOUR; h++) {
    for (let m = 0; m < 60; m += SLOT_DURATION_MIN) {
      const endH = h + Math.floor((m + SLOT_DURATION_MIN) / 60);
      const endM = (m + SLOT_DURATION_MIN) % 60;
      if (endH > WORK_END_HOUR) break;
      const start = `${dateStr}T${pad(h)}:${pad(m)}:00`;
      const end = `${dateStr}T${pad(endH)}:${pad(endM)}:00`;
      slots.push({ start, end });
    }
  }
  return slots;
}
function isBusy(slot, busyList) {
  const sStart = new Date(slot.start).getTime();
  const sEnd = new Date(slot.end).getTime();
  return busyList.some(b => {
    const bStart = new Date(b.start).getTime();
    const bEnd = new Date(b.end).getTime();
    return sStart < bEnd && sEnd > bStart;
  });
}

function findFreeSlots(dateStr, availabilityMap) {
  const slots = generateSlots(dateStr);
  const allBusy = Object.values(availabilityMap).flat();
  return slots.filter(slot => !isBusy(slot, allBusy));
}

function formatSlot(slot) {
  // slot times are in Iran local time already (from generateSlots)
  const s = new Date(slot.start);
  const e = new Date(slot.end);
  const pad = n => String(n).padStart(2, "0");
  // Use UTC getters since we stored as UTC-based Iran time
  return `${pad(s.getHours())}:${pad(s.getMinutes())} - ${pad(e.getHours())}:${pad(e.getMinutes())}`;
}

function formatDateTime(iso) {
  // Exchange returns Iran local time directly
  const d = new Date(iso);
  const pad = n => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}


// ─── EWS: Create Meeting with attendees + room ────────────────────────────────
// Convert Iran local time string to UTC ISO for EWS
// Input: "2026-04-19T11:00:00" (Iran time)
// Output: "2026-04-19T07:30:00" (UTC)
function iranToUTC(localISO) {
  // Parse as local string manually to avoid JS timezone issues
  const [datePart, timePart] = localISO.replace('Z','').split('T');
  const [year, month, day] = datePart.split('-').map(Number);
  const [hour, minute, second] = (timePart || '00:00:00').split(':').map(Number);
  // Create UTC date then subtract Iran offset (3h30m = 210 min)
  const utcMs = Date.UTC(year, month-1, day, hour, minute, second || 0) - (210 * 60 * 1000);
  const utc = new Date(utcMs);
  const pad = n => String(n).padStart(2, "0");
  return `${utc.getUTCFullYear()}-${pad(utc.getUTCMonth()+1)}-${pad(utc.getUTCDate())}T${pad(utc.getUTCHours())}:${pad(utc.getUTCMinutes())}:00`;
}

// Convert UTC ISO from EWS to Iran local time string for display
function utcToIran(utcISO) {
  const utcMs = new Date(utcISO).getTime();
  const iranMs = utcMs + (210 * 60 * 1000);
  const d = new Date(iranMs);
  const pad = n => String(n).padStart(2, "0");
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth()+1)}-${pad(d.getUTCDate())}T${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:00`;
}

// ─── Recurring availability + room-acceptance verification ────────────────────

// Compute the date (YYYY-MM-DD) of every occurrence of a recurring series.
// Mirrors EXACTLY the pattern logic in createMeeting so the availability check
// matches what Exchange will actually create. Capped at 200 to avoid runaway.
function computeOccurrenceDates(startDateStr, recurrence) {
  const { type, interval = 1, endDate, occurrences } = recurrence;
  const [y, mo, dd] = startDateStr.split('-').map(Number);
  const first = new Date(Date.UTC(y, mo - 1, dd));
  const dates = [];
  const CAP = 200;
  const pad = n => String(n).padStart(2, '0');
  const fmt = d => `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
  const endLimit = endDate ? new Date(Date.UTC(...endDate.split('-').map((v, i) => i === 1 ? Number(v) - 1 : Number(v)))) : null;
  const maxCount = endDate ? CAP : Math.min(occurrences || 10, CAP);

  let cur = new Date(first.getTime());
  for (let i = 0; i < maxCount; i++) {
    if (endLimit && cur.getTime() > endLimit.getTime()) break;
    dates.push(fmt(cur));
    if (type === 'daily') {
      cur = new Date(Date.UTC(cur.getUTCFullYear(), cur.getUTCMonth(), cur.getUTCDate() + interval));
    } else if (type === 'weekly') {
      cur = new Date(Date.UTC(cur.getUTCFullYear(), cur.getUTCMonth(), cur.getUTCDate() + 7 * interval));
    } else if (type === 'monthly') {
      // Absolute monthly: same day-of-month each interval months (matches AbsoluteMonthlyRecurrence).
      // Exchange puts day 29-31 on the LAST day of shorter months (e.g. 31st -> Nov 30), never rolls into next month.
      const ny = cur.getUTCFullYear(), nm = cur.getUTCMonth() + interval;
      const lastDay = new Date(Date.UTC(ny, nm + 1, 0)).getUTCDate();
      cur = new Date(Date.UTC(ny, nm, Math.min(dd, lastDay)));
    } else {
      break;
    }
  }
  return dates;
}

// For a recurring series, check the room + attendees on EVERY occurrence date.
// Returns { ok: bool, conflicts: [{date, busy:[emails]}], checkedCount }.
async function checkRecurringAvailability(checkEmails, startTime, endTime, occurrenceDates) {
  // One free/busy query per window of <= 40 days (EWS caps GetUserAvailability at 42 days) instead of
  // one query per occurrence. A failed window marks all its dates as conflicts (fail closed).
  const conflicts = [];
  const unknown = new Set();
  const WINDOW_DAYS = 40;
  const toMs = d => { const [y, mo, dd] = d.split('-').map(Number); return Date.UTC(y, mo - 1, dd); };
  let i = 0;
  while (i < occurrenceDates.length) {
    let j = i;
    while (j + 1 < occurrenceDates.length && toMs(occurrenceDates[j + 1]) - toMs(occurrenceDates[i]) < WINDOW_DAYS * 86400000) j++;
    const batch = occurrenceDates.slice(i, j + 1);
    let avail = null;
    try {
      avail = await getAvailability(checkEmails, `${batch[0]}T00:00:00`, `${batch[batch.length - 1]}T23:59:59`);
    } catch (e) { avail = null; }
    if (avail && avail.__errors) avail.__errors.forEach(e => unknown.add(e));
    for (const date of batch) {
      if (!avail) { conflicts.push({ date, busy: [T.checkFailed] }); continue; }
      const slot = { start: `${date}T${startTime}`, end: `${date}T${endTime}` };
      const busy = checkEmails.filter(email => isBusy(slot, avail[email] || []));
      if (busy.length) conflicts.push({ date, busy });
    }
    i = j + 1;
  }
  return { ok: conflicts.length === 0 && unknown.size === 0, conflicts, checkedCount: occurrenceDates.length, unknown: [...unknown] };
}

// Read a room's OWN calendar via ExchangeImpersonation for a date range.
// Returns array of { subject, startMs, endMs } with times as UTC ms.
// Because all rooms are auto-accept, a meeting the room accepted WILL appear here;
// one it declined (conflict or no access) will NOT.
async function getRoomCalendar(roomEmail, startDate, endDate) {
  const xml = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Body>
    <m:FindItem Traversal="Shallow">
      <m:ItemShape><t:BaseShape>IdOnly</t:BaseShape>
        <t:AdditionalProperties>
          <t:FieldURI FieldURI="item:Subject"/>
          <t:FieldURI FieldURI="calendar:Start"/>
          <t:FieldURI FieldURI="calendar:End"/>
          <t:FieldURI FieldURI="calendar:UID"/>
        </t:AdditionalProperties>
      </m:ItemShape>
      <m:CalendarView MaxEntriesReturned="1000" StartDate="${xmlEscape(startDate)}T00:00:00" EndDate="${xmlEscape(endDate)}T23:59:59"/>
      <m:ParentFolderIds><t:DistinguishedFolderId Id="calendar"/></m:ParentFolderIds>
    </m:FindItem>
  </soap:Body>
</soap:Envelope>`;
  const resp = await ewsRequest(SVC_USERNAME, SVC_PASSWORD, xml, roomEmail);
  if (/ResponseClass="Error"/.test(resp)) throw new Error("room calendar read failed");
  const events = [];
  const itemRegex = /<(?:[^:>]+:)?CalendarItem>([\s\S]*?)<\/(?:[^:>]+:)?CalendarItem>/g;
  let m;
  while ((m = itemRegex.exec(resp)) !== null) {
    const id = (m[1].match(/<(?:[^:>]+:)?ItemId[^>]+Id="([^"]+)"/) || [])[1] || null;
    const uid = (m[1].match(/<(?:[^:>]+:)?UID>([^<]+)</) || [])[1] || null;
    const subject = (m[1].match(/<(?:[^:>]+:)?Subject>([^<]*)</) || [])[1] || "";
    const start = (m[1].match(/<(?:[^:>]+:)?Start>([^<]*)</) || [])[1];
    const end = (m[1].match(/<(?:[^:>]+:)?End>([^<]*)</) || [])[1];
    if (start && end) events.push({ id, uid, subject, startMs: ewsTimeToMs(start), endMs: ewsTimeToMs(end) });
  }
  // Some Exchange builds do not return calendar:UID from FindItem — fetch missing ones with GetItem
  const missing = events.filter(e => !e.uid && e.id).map(e => e.id);
  if (missing.length) {
    const uids = await getItemUids(roomEmail, missing);
    events.forEach(e => { if (!e.uid && e.id && uids[e.id]) e.uid = uids[e.id]; });
  }
  return events;
}

// After booking, verify the room actually accepted EVERY occurrence by reading the
// room's own calendar. occurrenceDates: [YYYY-MM-DD]; startTime/endTime: "HH:MM:SS" Iran-local.
// Returns { ok: true } or { ok: false, missing: [dateStr,...] }.
// Waits before each room-calendar check after booking (cumulative ~15 s). Accepted bookings return at the
// first successful check; only a real decline waits the full schedule before rolling back.
const ROOM_VERIFY_SCHEDULE_MS = [3000, 3000, 4000, 5000];

async function verifyRoomAcceptedSeries(roomEmail, occurrenceDates, startTime, endTime, uid) {
  // Confirms the room accepted THIS meeting (same calendar:UID) for every occurrence — not merely that
  // the room is occupied at that time (which is also true when someone else won the room in a race).
  // Polls, because the room's booking assistant can take longer than a few seconds under load.
  if (!occurrenceDates.length) return { ok: true };
  if (!uid) return { ok: true, inconclusive: true, error: "meeting UID unknown" };
  const firstDate = occurrenceDates[0];
  const lastDate = occurrenceDates[occurrenceDates.length - 1];
  let missing = occurrenceDates, readOnce = false, lastError = null;
  for (const wait of ROOM_VERIFY_SCHEDULE_MS) {
    await new Promise(r => setTimeout(r, wait));
    let roomEvents;
    try { roomEvents = await getRoomCalendar(roomEmail, firstDate, lastDate); readOnce = true; }
    catch (e) { lastError = e.message; continue; }
    missing = occurrenceDates.filter(date => {
      const s = iranLocalToMs(`${date}T${startTime}`), e = iranLocalToMs(`${date}T${endTime}`);
      const mid = s + (e - s) / 2;
      return !roomEvents.some(ev => ev.uid === uid && ev.startMs <= mid && ev.endMs > mid);
    });
    if (!missing.length) return { ok: true };
  }
  // Could never read the room calendar -> inconclusive: keep the booking rather than delete a good one
  if (!readOnce) return { ok: true, inconclusive: true, error: lastError };
  return { ok: false, missing };
}

// Iran-local "YYYY-MM-DDTHH:MM[:SS]" -> UTC epoch ms (Iran = UTC+3:30, no DST)
function iranLocalToMs(s) {
  const [d, t = "00:00:00"] = String(s).replace("Z", "").split("T");
  const [y, mo, dd] = d.split("-").map(Number);
  const [h, mi, se] = t.split(":").map(Number);
  return Date.UTC(y, mo - 1, dd, h, mi, se || 0) - 210 * 60000;
}
// Time string returned by EWS -> UTC epoch ms. EWS returns UTC with 'Z';
// a value without a zone designator is treated as Iran local.
function ewsTimeToMs(s) {
  if (!s) return NaN;
  return /(Z|[+-]\d{2}:\d{2})$/.test(s) ? new Date(s).getTime() : iranLocalToMs(s);
}
function xmlDecode(s) {
  return String(s || "").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&(#39|apos);/g, "'").replace(/&amp;/g, "&");
}

// Find the just-created meeting in the organizer's calendar (same subject AND same start
// instant) and delete the WHOLE series. Used to roll back when the room declined any occurrence.
// Never falls back to "any meeting with this subject" — deleting the wrong meeting is worse
// than leaving the user a clear message to check manually.
async function rollbackMeeting(userEmail, { subject, start }) {
  try {
    const dateStr = start.split("T")[0];
    const events = await listEvents(userEmail, `${dateStr}T00:00:00`, `${dateStr}T23:59:59`);
    const targetMs = iranLocalToMs(start);
    const matches = events.filter(e =>
      xmlDecode(e.subject).trim() === subject.trim() && ewsTimeToMs(e.start) === targetMs
    );
    if (matches.length === 0) return { rolledBack: false, reason: "meeting not found for rollback" };
    if (matches.length > 1) return { rolledBack: false, reason: "more than one identical meeting found — not deleting automatically" };
    await deleteEvent(userEmail, { itemId: matches[0].id, changeKey: matches[0].changeKey, affectedOccurrences: 'AllOccurrences' });
    return { rolledBack: true };
  } catch (e) {
    return { rolledBack: false, reason: e.message };
  }
}

async function createMeeting(userEmail, { subject, start, end, roomEmail, attendeeEmails, body, recurrence }) {
  const required = [...(attendeeEmails || []), ...(roomEmail ? [roomEmail] : [])].map(e =>
    `<t:Attendee><t:Mailbox><t:EmailAddress>${xmlEscape(e)}</t:EmailAddress></t:Mailbox></t:Attendee>`
  ).join("");

  let recurrenceXml = '';
  if (recurrence && recurrence.type) {
    const { type, interval = 1, endDate, occurrences } = recurrence;
    let patternXml = '';
    if (type === 'daily') {
      patternXml = `<t:DailyRecurrence><t:Interval>${xmlEscape(interval)}</t:Interval></t:DailyRecurrence>`;
    } else if (type === 'weekly') {
      const days = ['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'];
      const [dp] = start.split('T');
      const [y,mo,dd] = dp.split('-').map(Number);
      const dow = days[new Date(Date.UTC(y, mo-1, dd)).getUTCDay()];
      patternXml = `<t:WeeklyRecurrence><t:Interval>${xmlEscape(interval)}</t:Interval><t:DaysOfWeek>${xmlEscape(dow)}</t:DaysOfWeek></t:WeeklyRecurrence>`;
    } else if (type === 'monthly') {
      const dayOfMonth = parseInt(start.split('T')[0].split('-')[2]);
      patternXml = `<t:AbsoluteMonthlyRecurrence><t:Interval>${xmlEscape(interval)}</t:Interval><t:DayOfMonth>${xmlEscape(dayOfMonth)}</t:DayOfMonth></t:AbsoluteMonthlyRecurrence>`;
    }
    const startDate = start.split('T')[0];
    let rangeXml = endDate
      ? `<t:EndDateRecurrence><t:StartDate>${xmlEscape(startDate)}</t:StartDate><t:EndDate>${xmlEscape(endDate)}</t:EndDate></t:EndDateRecurrence>`
      : `<t:NumberedRecurrence><t:StartDate>${xmlEscape(startDate)}</t:StartDate><t:NumberOfOccurrences>${xmlEscape(occurrences || 10)}</t:NumberOfOccurrences></t:NumberedRecurrence>`;
    recurrenceXml = `<t:Recurrence>${patternXml}${rangeXml}</t:Recurrence>`;
  }

  const xml = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Body>
    <m:CreateItem SendMeetingInvitations="SendToAllAndSaveCopy">
      <m:SavedItemFolderId><t:DistinguishedFolderId Id="calendar"/></m:SavedItemFolderId>
      <m:Items>
        <t:CalendarItem>
          <t:Subject>${xmlEscape(subject)}</t:Subject>
          ${body ? `<t:Body BodyType="Text">${xmlEscape(body)}</t:Body>` : ""}
          <t:Start>${xmlEscape(start)}</t:Start>
          <t:End>${xmlEscape(end)}</t:End>
          ${roomEmail ? `<t:Location>${xmlEscape(getRoomDisplayName(roomEmail))}</t:Location>` : ""}
          ${recurrenceXml}
          ${required ? `<t:RequiredAttendees>${required}</t:RequiredAttendees>` : ""}
        </t:CalendarItem>
      </m:Items>
    </m:CreateItem>
  </soap:Body>
</soap:Envelope>`;
  const resp = await ewsRequest(SVC_USERNAME, SVC_PASSWORD, xml, userEmail);
  // EWS reports most failures as HTTP 200 + ResponseClass="Error". Surface them instead of
  // reporting a meeting that was never created.
  if (/ResponseClass="Error"/.test(resp)) {
    const why = (resp.match(/<(?:[^:>]+:)?MessageText>([^<]+)</) || [])[1]
             || (resp.match(/<(?:[^:>]+:)?ResponseCode>([^<]+)</) || [])[1]
             || "request rejected";
    throw new Error(`Exchange: ${why}`);
  }
  const itemId = (resp.match(/<(?:[^:>]+:)?ItemId[^>]+Id="([^"]+)"/) || [])[1] || null;
  const changeKey = (resp.match(/<(?:[^:>]+:)?ItemId[^>]+ChangeKey="([^"]+)"/) || [])[1] || null;
  return { itemId, changeKey };
}

// calendar:UID is shared by every copy of a meeting (organizer, attendees, room) — the reliable way to
// tell OUR meeting apart from someone else's in the same room slot.
async function getItemUids(mailbox, itemIds) {
  if (!itemIds || !itemIds.length) return {};
  const xml = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Body>
    <m:GetItem>
      <m:ItemShape><t:BaseShape>IdOnly</t:BaseShape>
        <t:AdditionalProperties><t:FieldURI FieldURI="calendar:UID"/></t:AdditionalProperties>
      </m:ItemShape>
      <m:ItemIds>${itemIds.map(id => `<t:ItemId Id="${xmlEscape(id)}"/>`).join("")}</m:ItemIds>
    </m:GetItem>
  </soap:Body>
</soap:Envelope>`;
  const resp = await ewsRequest(SVC_USERNAME, SVC_PASSWORD, xml, mailbox);
  const out = {};
  const re = /<(?:[^:>]+:)?CalendarItem>([\s\S]*?)<\/(?:[^:>]+:)?CalendarItem>/g;
  let m;
  while ((m = re.exec(resp)) !== null) {
    const id = (m[1].match(/<(?:[^:>]+:)?ItemId[^>]+Id="([^"]+)"/) || [])[1];
    const uid = (m[1].match(/<(?:[^:>]+:)?UID>([^<]+)</) || [])[1];
    if (id && uid) out[id] = uid;
  }
  return out;
}

// Delete exactly the item we created (the series master for recurring meetings), cancelling invites.
async function deleteItemById(mailbox, itemId) {
  const xml = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Body>
    <m:DeleteItem DeleteType="MoveToDeletedItems" SendMeetingCancellations="SendToAllAndSaveCopy">
      <m:ItemIds><t:ItemId Id="${xmlEscape(itemId)}"/></m:ItemIds>
    </m:DeleteItem>
  </soap:Body>
</soap:Envelope>`;
  const resp = await ewsRequest(SVC_USERNAME, SVC_PASSWORD, xml, mailbox);
  if (/ResponseClass="Error"/.test(resp)) {
    throw new Error((resp.match(/<(?:[^:>]+:)?MessageText>([^<]+)</) || [])[1] || "delete failed");
  }
}


// ─── EWS: Calendar CRUD ───────────────────────────────────────────────────────
function extractEvents(xml) {
  const events = [];
  const itemRegex = /<(?:[^:>]+:)?CalendarItem>([\s\S]*?)<\/(?:[^:>]+:)?CalendarItem>/g;
  let match;
  while ((match = itemRegex.exec(xml)) !== null) {
    const item = match[1];
    const id = (item.match(/<(?:[^:>]+:)?ItemId[^>]+Id="([^"]+)"/) || [])[1];
    const changeKey = (item.match(/<(?:[^:>]+:)?ItemId[^>]+ChangeKey="([^"]+)"/) || [])[1];
    const subject = (item.match(/<(?:[^:>]+:)?Subject>([^<]*)</) || [])[1];
    const start = (item.match(/<(?:[^:>]+:)?Start>([^<]*)</) || [])[1];
    const end = (item.match(/<(?:[^:>]+:)?End>([^<]*)</) || [])[1];
    const location = (item.match(/<(?:[^:>]+:)?Location>([^<]*)</) || [])[1];
    if (id) events.push({ id, changeKey, subject, start, end, location });
  }
  return events;
}

async function getEventDetails(userEmail, itemIds) {
  const ids = itemIds.map(id => `<t:ItemId Id="${xmlEscape(id)}"/>`).join("");
  const xml = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Body>
    <m:GetItem>
      <m:ItemShape>
        <t:BaseShape>AllProperties</t:BaseShape>
        <t:AdditionalProperties>
          <t:FieldURI FieldURI="calendar:RequiredAttendees"/>
          <t:FieldURI FieldURI="calendar:OptionalAttendees"/>
          <t:FieldURI FieldURI="calendar:Organizer"/>
        </t:AdditionalProperties>
      </m:ItemShape>
      <m:ItemIds>${ids}</m:ItemIds>
    </m:GetItem>
  </soap:Body>
</soap:Envelope>`;
  const response = await ewsRequest(SVC_USERNAME, SVC_PASSWORD, xml, userEmail);
  const details = {};
  const itemRegex = /<(?:[^:>]+:)?CalendarItem>([\s\S]*?)<\/(?:[^:>]+:)?CalendarItem>/g;
  let match;
  while ((match = itemRegex.exec(response)) !== null) {
    const item = match[1];
    const id = (item.match(/<(?:[^:>]+:)?ItemId[^>]+Id="([^"]+)"/) || [])[1];
    if (!id) continue;
    const attendees = [];
    const reqBlock = (item.match(/<(?:[^:>]+:)?RequiredAttendees>([\s\S]*?)<\/(?:[^:>]+:)?RequiredAttendees>/) || [])[1] || "";
    const attRegex = /<(?:[^:>]+:)?Attendee>([\s\S]*?)<\/(?:[^:>]+:)?Attendee>/g;
    let am;
    while ((am = attRegex.exec(reqBlock)) !== null) {
      const name = (am[1].match(/<(?:[^:>]+:)?Name>([^<]+)</) || [])[1];
      const email = (am[1].match(/<(?:[^:>]+:)?EmailAddress>([^<]+)</) || [])[1];
      if (email) attendees.push({ name: name || email, email, type: "required" });
    }
    const optBlock = (item.match(/<(?:[^:>]+:)?OptionalAttendees>([\s\S]*?)<\/(?:[^:>]+:)?OptionalAttendees>/) || [])[1] || "";
    const optRegex = /<(?:[^:>]+:)?Attendee>([\s\S]*?)<\/(?:[^:>]+:)?Attendee>/g;
    let om;
    while ((om = optRegex.exec(optBlock)) !== null) {
      const name = (om[1].match(/<(?:[^:>]+:)?Name>([^<]+)</) || [])[1];
      const email = (om[1].match(/<(?:[^:>]+:)?EmailAddress>([^<]+)</) || [])[1];
      if (email) attendees.push({ name: name || email, email, type: "optional" });
    }
    const orgBlock = (item.match(/<(?:[^:>]+:)?Organizer>([\s\S]*?)<\/(?:[^:>]+:)?Organizer>/) || [])[1] || "";
    const orgName = (orgBlock.match(/<(?:[^:>]+:)?Name>([^<]+)</) || [])[1];
    const orgEmail = (orgBlock.match(/<(?:[^:>]+:)?EmailAddress>([^<]+)</) || [])[1];
    const start    = (item.match(/<(?:[^:>]+:)?Start>([^<]+)</) || [])[1];
    const end      = (item.match(/<(?:[^:>]+:)?End>([^<]+)</) || [])[1];
    const location = (item.match(/<(?:[^:>]+:)?Location>([^<]+)</) || [])[1];
    details[id] = { attendees, organizer: orgEmail ? { name: orgName || orgEmail, email: orgEmail } : null, start, end, location };
  }
  return details;
}

async function listEvents(userEmail, start, end) {
  // Always use full day range — never cut off at current time
  if (start && !start.includes('T')) start = start + 'T00:00:00';
  if (end && !end.includes('T')) end = end + 'T23:59:59';
  if (start && start.match(/T\d{2}:\d{2}$/)) start = start + ':00';
  if (end && end.match(/T\d{2}:\d{2}$/)) end = end + ':00';
  // Force start to beginning of day — never use mid-day start
  if (start) start = start.substring(0, 10) + 'T00:00:00';
  if (end) end = end.substring(0, 10) + 'T23:59:59';
  const xml = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Body>
    <m:FindItem Traversal="Shallow">
      <m:ItemShape><t:BaseShape>AllProperties</t:BaseShape></m:ItemShape>
      <m:CalendarView MaxEntriesReturned="100" StartDate="${xmlEscape(start)}" EndDate="${xmlEscape(end)}"/>
      <m:ParentFolderIds><t:DistinguishedFolderId Id="calendar"/></m:ParentFolderIds>
    </m:FindItem>
  </soap:Body>
</soap:Envelope>`;
  const events = extractEvents(await ewsRequest(SVC_USERNAME, SVC_PASSWORD, xml, userEmail));
  if (!events.length) return events;
  try {
    const details = await getEventDetails(userEmail, events.map(e => e.id));
    return events.map(e => ({ ...e, ...(details[e.id] || {}) }));
  } catch {
    return events;
  }
}

async function getRecurringMasterId(userEmail, itemId) {
  // Get the RecurringMasterId for an occurrence of a recurring series
  const xml = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Body>
    <m:GetItem>
      <m:ItemShape>
        <t:BaseShape>IdOnly</t:BaseShape>
        <t:AdditionalProperties>
          <t:FieldURI FieldURI="calendar:IsRecurring"/>
          <t:FieldURI FieldURI="item:Subject"/>
        </t:AdditionalProperties>
      </m:ItemShape>
      <m:ItemIds><t:ItemId Id="${xmlEscape(itemId)}"/></m:ItemIds>
    </m:GetItem>
  </soap:Body>
</soap:Envelope>`;
  try {
    const resp = await ewsRequest(SVC_USERNAME, SVC_PASSWORD, xml, userEmail);
    const isRecurring = resp.includes('<t:IsRecurring>true</t:IsRecurring>');
    // Get RecurringMasterId using OccurrenceItemId
    if (isRecurring) {
      const masterXml = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Body>
    <m:GetItem>
      <m:ItemShape><t:BaseShape>IdOnly</t:BaseShape></m:ItemShape>
      <m:ItemIds><t:RecurringMasterItemId OccurrenceId="${xmlEscape(itemId)}"/></m:ItemIds>
    </m:GetItem>
  </soap:Body>
</soap:Envelope>`;
      const masterResp = await ewsRequest(SVC_USERNAME, SVC_PASSWORD, masterXml, userEmail);
      const masterId = (masterResp.match(/<(?:[^:>]+:)?ItemId[^>]+Id="([^"]+)"/) || [])[1];
      const masterCK = (masterResp.match(/<(?:[^:>]+:)?ItemId[^>]+ChangeKey="([^"]+)"/) || [])[1];
      if (masterId) return { masterId, masterCK, isRecurring: true };
    }
    return { masterId: null, masterCK: null, isRecurring: false };
  } catch(e) { return { masterId: null, masterCK: null, isRecurring: false }; }
}

async function deleteEvent(userEmail, { itemId, changeKey, affectedOccurrences = 'AllOccurrences' }) {
  if (affectedOccurrences === 'SpecifiedOccurrenceOnly') {
    const xml = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Body>
    <m:DeleteItem DeleteType="MoveToDeletedItems" SendMeetingCancellations="SendToAllAndSaveCopy" AffectedTaskOccurrences="SpecifiedOccurrenceOnly">
      <m:ItemIds><t:ItemId Id="${xmlEscape(itemId)}" ChangeKey="${xmlEscape(changeKey)}"/></m:ItemIds>
    </m:DeleteItem>
  </soap:Body>
</soap:Envelope>`;
    assertEwsSuccess(await ewsRequest(SVC_USERNAME, SVC_PASSWORD, xml, userEmail), "Delete");
    return;
  }
  if (affectedOccurrences === 'AllFollowingOccurrences') {
    const xml = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Body>
    <m:DeleteItem DeleteType="MoveToDeletedItems" SendMeetingCancellations="SendToAllAndSaveCopy">
      <m:ItemIds><t:ItemId Id="${xmlEscape(itemId)}" ChangeKey="${xmlEscape(changeKey)}"/></m:ItemIds>
    </m:DeleteItem>
  </soap:Body>
</soap:Envelope>`;
    assertEwsSuccess(await ewsRequest(SVC_USERNAME, SVC_PASSWORD, xml, userEmail), "Delete");
    return;
  }
  // AllOccurrences — get recurring master and delete entire series
  let deleteId = itemId;
  let deleteCK = changeKey;

  // For series deletion, get the recurring master first
  if (affectedOccurrences === 'AllOccurrences') {
    const { masterId, masterCK, isRecurring } = await getRecurringMasterId(userEmail, itemId);
    if (isRecurring && masterId) {
      deleteId = masterId;
      deleteCK = masterCK;
    }
  }

  const xml = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Body>
    <m:DeleteItem DeleteType="MoveToDeletedItems" SendMeetingCancellations="SendToAllAndSaveCopy">
      <m:ItemIds><t:ItemId Id="${xmlEscape(deleteId)}" ChangeKey="${xmlEscape(deleteCK || changeKey)}"/></m:ItemIds>
    </m:DeleteItem>
  </soap:Body>
</soap:Envelope>`;
  assertEwsSuccess(await ewsRequest(SVC_USERNAME, SVC_PASSWORD, xml, userEmail), "Delete");
}

async function updateEvent(userEmail, { itemId, changeKey, subject, start, end, location, roomEmail, body, attendeeEmails, affectedOccurrences = 'AllOccurrences' }) {
  const fields = [];
  if (subject) fields.push(`<t:SetItemField><t:FieldURI FieldURI="item:Subject"/><t:CalendarItem><t:Subject>${xmlEscape(subject)}</t:Subject></t:CalendarItem></t:SetItemField>`);
  if (start) fields.push(`<t:SetItemField><t:FieldURI FieldURI="calendar:Start"/><t:CalendarItem><t:Start>${xmlEscape(start)}</t:Start></t:CalendarItem></t:SetItemField>`);
  if (end) fields.push(`<t:SetItemField><t:FieldURI FieldURI="calendar:End"/><t:CalendarItem><t:End>${xmlEscape(end)}</t:End></t:CalendarItem></t:SetItemField>`);
  if (location !== undefined) {
    fields.push(`<t:DeleteItemField><t:FieldURI FieldURI="calendar:Location"/></t:DeleteItemField>`);
    if (location) fields.push(`<t:SetItemField><t:FieldURI FieldURI="calendar:Location"/><t:CalendarItem><t:Location>${xmlEscape(getRoomDisplayName(location))}</t:Location></t:CalendarItem></t:SetItemField>`);
  }
  if (body) fields.push(`<t:SetItemField><t:FieldURI FieldURI="item:Body"/><t:CalendarItem><t:Body BodyType="Text">${xmlEscape(body)}</t:Body></t:CalendarItem></t:SetItemField>`);
  // Handle attendees: first read current event to preserve existing attendees/room
  if (attendeeEmails !== undefined || roomEmail !== undefined) {
    // Get current attendees from event
    let currentAttendees = [];
    try {
      const details = await getEventDetails(userEmail, [itemId]);
      currentAttendees = (details[itemId] && details[itemId].attendees) ? details[itemId].attendees.map(a => a.email) : [];
    } catch {}
    // Determine final attendee list
    let finalList;
    if (attendeeEmails !== undefined && roomEmail !== undefined) {
      // Both provided: use attendeeEmails + new room
      finalList = [...attendeeEmails.filter(e => !e.includes('room-')), roomEmail];
    } else if (attendeeEmails !== undefined) {
      // Only attendees: merge with existing room
      const existingRoom = currentAttendees.find(e => e.includes('room-'));
      finalList = [...attendeeEmails.filter(e => !e.includes('room-')), ...(existingRoom ? [existingRoom] : [])];
    } else {
      // Only room: merge with existing human attendees
      finalList = [...currentAttendees.filter(e => !e.includes('room-')), roomEmail];
    }
    fields.push(`<t:DeleteItemField><t:FieldURI FieldURI="calendar:RequiredAttendees"/></t:DeleteItemField>`);
    if (finalList.length > 0) {
      const attendeeXml = finalList.map(e =>
        `<t:Attendee><t:Mailbox><t:EmailAddress>${xmlEscape(e)}</t:EmailAddress></t:Mailbox></t:Attendee>`
      ).join("");
      fields.push(`<t:SetItemField><t:FieldURI FieldURI="calendar:RequiredAttendees"/><t:CalendarItem><t:RequiredAttendees>${attendeeXml}</t:RequiredAttendees></t:CalendarItem></t:SetItemField>`);
    }
  }
  // For recurring events: get master ID when updating all occurrences
  let useItemId = itemId;
  let useChangeKey = changeKey;
  if (affectedOccurrences === 'AllOccurrences') {
    try {
      const { masterId, masterCK, isRecurring } = await getRecurringMasterId(userEmail, itemId);
      if (isRecurring && masterId) { useItemId = masterId; useChangeKey = masterCK; }
    } catch(e) {}
  }
  const xml = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Body>
    <m:UpdateItem MessageDisposition="SaveOnly" ConflictResolution="AutoResolve"
                  SendMeetingInvitationsOrCancellations="SendToAllAndSaveCopy">
      <m:ItemChanges>
        <t:ItemChange>
          <t:ItemId Id="${xmlEscape(useItemId)}" ChangeKey="${xmlEscape(useChangeKey)}"/>
          <t:Updates>${fields.join("")}</t:Updates>
        </t:ItemChange>
      </m:ItemChanges>
    </m:UpdateItem>
  </soap:Body>
</soap:Envelope>`;
  const resp = await ewsRequest(SVC_USERNAME, SVC_PASSWORD, xml, userEmail);
  try { assertEwsSuccess(resp, "Update"); }
  catch (e) {
    // AutoResolve refuses an update made with an out-of-date change key
    if (/ErrorIrresolvableConflict/.test(e.message)) e.message += " The event changed after it was read: call list_events for its current change_key, then try again.";
    throw e;
  }
}


// ─── EWS: List Emails ────────────────────────────────────────────────────────
async function listEmails(userEmail, opts) {
  const { unreadOnly = false, from: fromFilter = null, startDate = null, endDate = null, maxCount = 20 } = opts || {};
  const restrictions = [];
  if (unreadOnly) restrictions.push('<t:IsEqualTo><t:FieldURI FieldURI="message:IsRead"/><t:FieldURIOrConstant><t:Constant Value="false"/></t:FieldURIOrConstant></t:IsEqualTo>');
  if (fromFilter) restrictions.push(`<t:Contains ContainmentMode="Substring" ContainmentComparison="IgnoreCase"><t:FieldURI FieldURI="message:From"/><t:Constant Value="${xmlEscape(fromFilter)}"/></t:Contains>`);
  if (startDate) restrictions.push(`<t:IsGreaterThanOrEqualTo><t:FieldURI FieldURI="item:DateTimeReceived"/><t:FieldURIOrConstant><t:Constant Value="${xmlEscape(startDate)}"/></t:FieldURIOrConstant></t:IsGreaterThanOrEqualTo>`);
  if (endDate) restrictions.push(`<t:IsLessThanOrEqualTo><t:FieldURI FieldURI="item:DateTimeReceived"/><t:FieldURIOrConstant><t:Constant Value="${xmlEscape(endDate)}"/></t:FieldURIOrConstant></t:IsLessThanOrEqualTo>`);
  // Always filter to real emails only (exclude MeetingRequest/Response/Cancellation)
  restrictions.push('<t:IsEqualTo><t:FieldURI FieldURI="item:ItemClass"/><t:FieldURIOrConstant><t:Constant Value="IPM.Note"/></t:FieldURIOrConstant></t:IsEqualTo>');
  const restriction = `<m:Restriction>${restrictions.length > 1 ? `<t:And>${restrictions.join("")}</t:And>` : restrictions[0]}</m:Restriction>`;
  const xml = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Body>
    <m:FindItem Traversal="Shallow">
      <m:ItemShape>
        <t:BaseShape>IdOnly</t:BaseShape>
        <t:AdditionalProperties>
          <t:FieldURI FieldURI="item:Subject"/>
          <t:FieldURI FieldURI="item:DateTimeReceived"/>
          <t:FieldURI FieldURI="message:From"/>
          <t:FieldURI FieldURI="message:IsRead"/>
          <t:FieldURI FieldURI="item:HasAttachments"/>
        </t:AdditionalProperties>
      </m:ItemShape>
      <m:IndexedPageItemView MaxEntriesReturned="${xmlEscape(maxCount)}" Offset="0" BasePoint="Beginning"/>
      ${restriction}
      <m:SortOrder><t:FieldOrder Order="Descending"><t:FieldURI FieldURI="item:DateTimeReceived"/></t:FieldOrder></m:SortOrder>
      <m:ParentFolderIds><t:DistinguishedFolderId Id="inbox"/></m:ParentFolderIds>
    </m:FindItem>
  </soap:Body>
</soap:Envelope>`;
  const response = await ewsRequest(SVC_USERNAME, SVC_PASSWORD, xml, userEmail);
  const emails = [];
  const itemRegex = /<(?:[^:>]+:)?Message>([\s\S]*?)<\/(?:[^:>]+:)?Message>/g;
  let match;
  while ((match = itemRegex.exec(response)) !== null) {
    const item = match[1];
    const id = (item.match(/<(?:[^:>]+:)?ItemId[^>]+Id="([^"]+)"/) || [])[1];
    const changeKey = (item.match(/<(?:[^:>]+:)?ItemId[^>]+ChangeKey="([^"]+)"/) || [])[1];
    const subject = (item.match(/<(?:[^:>]+:)?Subject>([^<]*)</) || [])[1] || "(No subject)";
    const received = (item.match(/<(?:[^:>]+:)?DateTimeReceived>([^<]+)</) || [])[1];
    const isRead = (item.match(/<(?:[^:>]+:)?IsRead>([^<]+)</) || [])[1] === "true";
    const hasAttachments = (item.match(/<(?:[^:>]+:)?HasAttachments>([^<]+)</) || [])[1] === "true";
    const fromName = (item.match(/<(?:[^:>]+:)?From>[\s\S]*?<(?:[^:>]+:)?Name>([^<]+)</) || [])[1];
    const fromEmail = (item.match(/<(?:[^:>]+:)?From>[\s\S]*?<(?:[^:>]+:)?EmailAddress>([^<]+)</) || [])[1];
    // Skip meeting responses/requests - they have no fromEmail in message:From field
    if (id && fromEmail) emails.push({ id, changeKey, subject, received, isRead, hasAttachments, fromName, fromEmail });
  }
  return emails;
}

async function getEmail(userEmail, itemId) {
  const xml = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Body>
    <m:GetItem>
      <m:ItemShape><t:BaseShape>AllProperties</t:BaseShape><t:BodyType>Text</t:BodyType></m:ItemShape>
      <m:ItemIds><t:ItemId Id="${xmlEscape(itemId)}"/></m:ItemIds>
    </m:GetItem>
  </soap:Body>
</soap:Envelope>`;
  const response = await ewsRequest(SVC_USERNAME, SVC_PASSWORD, xml, userEmail);
  const item = (response.match(/<(?:[^:>]+:)?Message>([\s\S]*?)<\/(?:[^:>]+:)?Message>/) || [])[1] || "";
  const subject = (item.match(/<(?:[^:>]+:)?Subject>([^<]*)</) || [])[1] || "(No subject)";
  const received = (item.match(/<(?:[^:>]+:)?DateTimeReceived>([^<]+)</) || [])[1];
  const fromName = (item.match(/<(?:[^:>]+:)?From>[\s\S]*?<(?:[^:>]+:)?Name>([^<]+)</) || [])[1];
  const fromEmail = (item.match(/<(?:[^:>]+:)?From>[\s\S]*?<(?:[^:>]+:)?EmailAddress>([^<]+)</) || [])[1];
  const bodyMatch = item.match(/<(?:[^:>]+:)?Body[^>]*>([\s\S]*?)<\/(?:[^:>]+:)?Body>/);
  // Strip tags until none are left (a single pass can leave fragments like "<<b>script>")
  let body = bodyMatch ? bodyMatch[1] : "";
  for (let prev = null; prev !== body; ) { prev = body; body = body.replace(/<[^>]+>/g, ""); }
  body = body.trim();
  try { await markEmailAsRead(userEmail, itemId); } catch (e) { console.error('[markEmailAsRead]', e.message); }
  return { subject, body, fromName, fromEmail, received };
}

async function markEmailAsRead(userEmail, itemId) {
  const xml = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Body>
    <m:UpdateItem MessageDisposition="SaveOnly" ConflictResolution="AlwaysOverwrite">
      <m:ItemChanges><t:ItemChange><t:ItemId Id="${xmlEscape(itemId)}"/>
        <t:Updates><t:SetItemField><t:FieldURI FieldURI="message:IsRead"/><t:Message><t:IsRead>true</t:IsRead></t:Message></t:SetItemField></t:Updates>
      </t:ItemChange></m:ItemChanges>
    </m:UpdateItem>
  </soap:Body>
</soap:Envelope>`;
  const resp = await ewsRequest(SVC_USERNAME, SVC_PASSWORD, xml, userEmail);

}


async function getAttachments(userEmail, itemId) {
  const xml1 = `<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"><soap:Body><m:GetItem><m:ItemShape><t:BaseShape>IdOnly</t:BaseShape><t:AdditionalProperties><t:FieldURI FieldURI="item:Attachments"/></t:AdditionalProperties></m:ItemShape><m:ItemIds><t:ItemId Id="${xmlEscape(itemId)}"/></m:ItemIds></m:GetItem></soap:Body></soap:Envelope>`;
  const response1 = await ewsRequest(SVC_USERNAME, SVC_PASSWORD, xml1, userEmail);
  const attachments = [];
  // Parse each FileAttachment block individually to keep name+attId+contentType together
  const attIdRe = /AttachmentId[^>]+Id="([^"]+)"/g;
  const nameRe = /<t:Name>([^<]+)<\/t:Name>/g;
  const ctRe = /<t:ContentType>([^<]+)<\/t:ContentType>/g;
  const attIds = [], names = [], cts = [];
  let m;
  while ((m = attIdRe.exec(response1)) !== null) attIds.push(m[1]);
  while ((m = nameRe.exec(response1)) !== null) names.push(m[1]);
  while ((m = ctRe.exec(response1)) !== null) cts.push(m[1]);
  attIds.forEach((attId, i) => {
    attachments.push({ attId, name: names[i] || "attachment", size: "0", contentType: cts[i] || "application/octet-stream" });
  });
  return attachments;
}

// ─── Email body formatter ─────────────────────────────────────────────────────
function formatEmailBody(body, direction = 'auto') {
  const escaped = body
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\n/g, '<br>');
  let dir;
  if (direction === 'rtl') dir = 'rtl';
  else if (direction === 'ltr') dir = 'ltr';
  else {
    // auto-detect: if majority of chars are RTL (Persian/Arabic), use rtl
    const rtlChars = (body.match(/[\u0600-\u06FF\u0750-\u077F]/g) || []).length;
    dir = rtlChars > body.length * 0.3 ? 'rtl' : 'ltr';
  }
  return `<div dir="${dir}" style="direction:${dir};text-align:${dir === 'rtl' ? 'right' : 'left'};font-family:Tahoma,Arial,sans-serif;font-size:14px;line-height:1.8;">${escaped}</div>`;
}

async function sendEmailEWS(userEmail, { to, cc = [], bcc = [], subject, body, direction = 'auto' }) {
  const toXml = to.map(e => `<t:Mailbox><t:EmailAddress>${xmlEscape(e)}</t:EmailAddress></t:Mailbox>`).join("");
  const ccXml = cc.map(e => `<t:Mailbox><t:EmailAddress>${xmlEscape(e)}</t:EmailAddress></t:Mailbox>`).join("");
  const bccXml = bcc.map(e => `<t:Mailbox><t:EmailAddress>${xmlEscape(e)}</t:EmailAddress></t:Mailbox>`).join("");
  const xml = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Body>
    <m:CreateItem MessageDisposition="SendAndSaveCopy">
      <m:SavedItemFolderId><t:DistinguishedFolderId Id="sentitems"/></m:SavedItemFolderId>
      <m:Items>
        <t:Message>
          <t:Subject>${xmlEscape(subject)}</t:Subject>
          <t:Body BodyType="HTML"><![CDATA[${formatEmailBody(body, direction)}]]></t:Body>
          <t:ToRecipients>${toXml}</t:ToRecipients>
          ${ccXml ? `<t:CcRecipients>${ccXml}</t:CcRecipients>` : ""}
          ${bccXml ? `<t:BccRecipients>${bccXml}</t:BccRecipients>` : ""}
        </t:Message>
      </m:Items>
    </m:CreateItem>
  </soap:Body>
</soap:Envelope>`;
  const resp = await ewsRequest(SVC_USERNAME, SVC_PASSWORD, xml, userEmail);
  assertEwsSuccess(resp, "Send");
}

async function replyEmailEWS(userEmail, { itemId, body, replyAll = false, direction = 'auto' }) {
  const tag = replyAll ? "ReplyAllToItem" : "ReplyToItem";
  const xml = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Body>
    <m:CreateItem MessageDisposition="SendAndSaveCopy">
      <m:SavedItemFolderId><t:DistinguishedFolderId Id="sentitems"/></m:SavedItemFolderId>
      <m:Items>
        <t:${tag}>
          <t:NewBodyContent BodyType="HTML"><![CDATA[${formatEmailBody(body, direction)}]]></t:NewBodyContent>
          <t:ReferenceItemId Id="${xmlEscape(itemId)}"/>
        </t:${tag}>
      </m:Items>
    </m:CreateItem>
  </soap:Body>
</soap:Envelope>`;
  const resp = await ewsRequest(SVC_USERNAME, SVC_PASSWORD, xml, userEmail);
  assertEwsSuccess(resp, "Reply");
}

// ─── Room Access Control ─────────────────────────────────────────────────────
// Rooms that only members of an AD group may book (checked live via LDAP, nested groups included).
// RESTRICTED_ROOMS (room → group mail) and EXCLUDED_ROOMS come from rooms.json.

async function checkUserInGroup(groupEmail, visited = new Set(), userEmail = null) {
  // Use LDAP for reliable nested group membership check
  if (!userEmail) return false;
  try {
    const client = await getLdapClient();
    if (!client) return false;
    // Get group DN from email
    const groupEntries = await ldapSearch(client, LDAP_BASE_DN,
      `(mail=${ldapEscape(groupEmail)})`, ['distinguishedName']);
    if (!groupEntries.length) {
      // Try by sAMAccountName (group alias without domain)
      const alias = groupEmail.split('@')[0];
      const aliasEntries = await ldapSearch(client, LDAP_BASE_DN,
        `(|(sAMAccountName=${ldapEscape(alias)})(cn=${ldapEscape(alias)}))`, ['distinguishedName']);
      if (!aliasEntries.length) { try { client.unbind(); } catch(e) {} return false; }
      const groupDN = ldapAttr(aliasEntries[0], 'distinguishedName');
      // Check if user is member (recursive via LDAP_MATCHING_RULE_IN_CHAIN)
      const userEntries = await ldapSearch(client, LDAP_BASE_DN,
        `(&(mail=${ldapEscape(userEmail)})(memberOf:1.2.840.113556.1.4.1941:=${ldapEscape(groupDN)}))`,
        ['mail']);
      try { client.unbind(); } catch(e) {}
      return userEntries.length > 0;
    }
    const groupDN = ldapAttr(groupEntries[0], 'distinguishedName');
    // LDAP_MATCHING_RULE_IN_CHAIN (1.2.840.113556.1.4.1941) checks nested membership
    const userEntries = await ldapSearch(client, LDAP_BASE_DN,
      `(&(mail=${ldapEscape(userEmail)})(memberOf:1.2.840.113556.1.4.1941:=${ldapEscape(groupDN)}))`,
      ['mail']);
    try { client.unbind(); } catch(e) {}
    return userEntries.length > 0;
  } catch(e) {
    console.error('[checkUserInGroup] LDAP error:', e.message);
    return false;
  }
}


async function expandGroup(groupEmail, impersonateEmail = null) {
  const xml = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Body>
    <m:ExpandDL>
      <m:Mailbox><t:EmailAddress>${xmlEscape(groupEmail)}</t:EmailAddress></m:Mailbox>
    </m:ExpandDL>
  </soap:Body>
</soap:Envelope>`;
  const response = await ewsRequest(SVC_USERNAME, SVC_PASSWORD, xml, impersonateEmail);
  const members = [];
  const regex = /<(?:[^:>]+:)?Mailbox>([\s\S]*?)<\/(?:[^:>]+:)?Mailbox>/g;
  let match;
  while ((match = regex.exec(response)) !== null) {
    const block = match[1];
    const email = (block.match(/<(?:[^:>]+:)?EmailAddress>([^<]+)</) || [])[1];
    const name = (block.match(/<(?:[^:>]+:)?Name>([^<]+)</) || [])[1];
    const type = (block.match(/<(?:[^:>]+:)?MailboxType>([^<]+)</) || [])[1];
    if (email && type !== "PublicDL") members.push({ email, name: name || email });
  }
  return members;
}

async function canUserBookRoom(roomEmail, userEmail = null) {
  if (EXCLUDED_ROOMS.includes(roomEmail)) {
    return { allowed: false, reason: T.roomUnavailable };
  }
  const groupEmail = RESTRICTED_ROOMS[roomEmail];
  if (!groupEmail) return { allowed: true };
  const isMember = await checkUserInGroup(groupEmail, new Set(), userEmail);
  if (isMember) return { allowed: true };
  const roomName = roomEmail.split("@")[0].replace("room-","").toUpperCase();
  return { allowed: false, reason: T.roomNoAccess(roomName) };
}

async function getAccessibleRooms(userEmail = null) {
  const allRooms = await getRooms();
  const result = [];
  for (const room of allRooms) {
    if (EXCLUDED_ROOMS.includes(room.email)) continue;
    const groupEmail = RESTRICTED_ROOMS[room.email];
    if (groupEmail) {
      const isMember = await checkUserInGroup(groupEmail, new Set(), userEmail);
      // Still include in list but mark as no_access
      result.push({ ...room, accessible: isMember, restricted: true });
    } else {
      result.push({ ...room, accessible: true, restricted: false });
    }
  }
  return result;
}

// Build a rich access-denied message. If date/start_time/duration_minutes are provided,
// it appends accessible rooms that are free in the requested slot. If any are missing
// (e.g. update_event with no time change), it safely returns just the base reason.
async function buildRoomDeniedMessage(reason, userEmail, date = null, start_time = null, duration_minutes = null) {
  let altText = '';
  try {
    if (userEmail && date && start_time && duration_minutes) {
      const accessibleRooms = await getAccessibleRooms(userEmail);
      const accessibleEmails = accessibleRooms.filter(r => r.accessible !== false).map(r => r.email);
      if (accessibleEmails.length) {
        const dayStart = `${date}T00:00:00`;
        const dayEnd = `${date}T23:59:59`;
        const slotStart = `${date}T${start_time}:00`;
        const [ah, am] = start_time.split(':').map(Number);
        const aEnd = ah * 60 + am + duration_minutes;
        const apad = n => String(n).padStart(2, "0");
        const slotEnd = `${date}T${apad(Math.floor(aEnd/60))}:${apad(aEnd%60)}:00`;
        const altAvail = await getAvailability(accessibleEmails, dayStart, dayEnd);
        const freeRooms = accessibleEmails.filter(e => !isBusy({ start: slotStart, end: slotEnd }, altAvail[e] || []));
        if (freeRooms.length) {
          altText = `\n\n${T.freeAccessibleRooms}:\n` +
            freeRooms.map(e => `  • ${getRoomDisplayName(e)} — ${e}`).join('\n');
        }
      }
    }
  } catch {}
  return `❌ ${reason}${altText}\n\n(${T.roomDeniedHint})`;
}


// ─── MCP Server ───────────────────────────────────────────────────────────────
// Per session: the access token of the latest request, and the user (email) who opened it
const sessionTokenMap = new Map();
const sessionOwner = new Map();

function forgetSession(id) {
  sessionLastSeen.delete(id); mcpTransports.delete(id); sessionTokenMap.delete(id); sessionOwner.delete(id);
}
function closeSession(id) {
  const tr = mcpTransports.get(id);
  forgetSession(id);
  if (tr) { try { tr.close(); } catch (e) {} }
}
// Keep a user below MAX_SESSIONS_PER_USER by closing their least recently used sessions
function evictOldestSessions(email) {
  const mine = [...sessionOwner].filter(([, owner]) => owner === email).map(([id]) => id)
    .sort((a, b) => (sessionLastSeen.get(a) || 0) - (sessionLastSeen.get(b) || 0));
  while (mine.length >= MAX_SESSIONS_PER_USER) closeSession(mine.shift());
}

// ── Rate limit: fixed one-minute window, in memory ─────────────────────────────
const RATE_USER_PER_MIN = 600;   // requests per signed-in user
const RATE_ANON_PER_MIN = 120;   // requests without a valid token, per client IP
const rateWindows = new Map();   // key -> { start, count }
function rateLimited(key, limit) {
  const now = Date.now();
  const w = rateWindows.get(key);
  if (!w || now - w.start >= 60000) { rateWindows.set(key, { start: now, count: 1 }); return false; }
  return ++w.count > limit;
}
// Behind the reverse proxy the peer is loopback; the proxy appends the real client to X-Forwarded-For.
function clientIp(req) {
  const peer = req.socket.remoteAddress || "";
  const forwarded = String(req.headers["x-forwarded-for"] || "").split(",").pop().trim();
  return /^(::1|127\.|::ffff:127\.)/.test(peer) && forwarded ? forwarded : peer;
}
function tooManyRequests(res) {
  res.writeHead(429, { "Content-Type": "application/json", "Retry-After": "60" });
  res.end(JSON.stringify({ error: "too_many_requests" }));
}

function readJsonBody(req, limit = 10 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0;
    req.on("data", c => { size += c.length; if (size > limit) { reject(new Error("body too large")); req.destroy(); } else chunks.push(c); });
    req.on("end", () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))); } catch (e) { reject(e); } });
    req.on("error", reject);
  });
}

// ── Idle session eviction ──────────────────────────────────────────────────────
// Each session holds a full McpServer (~1.5 MB measured). Clients (DXT, Claude apps) almost never close
// their sessions, so without eviction memory grows until the process is restarted. Sessions idle longer
// than SESSION_IDLE_MS are closed; a returning client gets HTTP 404 and transparently re-initialises.
const SESSION_IDLE_MS = 30 * 60 * 1000;
const SESSION_SWEEP_MS = 5 * 60 * 1000;
const sessionLastSeen = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [id, seen] of sessionLastSeen) {
    if (now - seen >= SESSION_IDLE_MS) closeSession(id);
  }
  for (const [key, w] of rateWindows) if (now - w.start >= 60000) rateWindows.delete(key);
}, SESSION_SWEEP_MS).unref();

// ── Previews before anything is sent or booked ─────────────────────────────────
// The server remembers each exact request it has shown a preview of, per user. Sending or booking
// only happens for a request that was previewed first: once, within 10 minutes. A changed recipient,
// text, time or room is a different request and gets a new preview.
const previews = createPreviewStore();
// send_email / reply_email have no confirm flag: repeating the identical request is the confirmation
function confirmSend(userEmail, tool, request) {
  if (previews.consume(userEmail, tool, request)) return true;
  previews.remember(userEmail, tool, request);
  return false;
}
// Tools with a confirmed flag: confirmed=true only counts for a request that was previewed first;
// otherwise the call is answered with the preview.
function confirmedAfterPreview(userEmail, tool, { confirmed, ...request }) {
  if (confirmed === true && previews.consume(userEmail, tool, request)) return true;
  previews.remember(userEmail, tool, request);
  return false;
}

function buildMcpServer(bearerToken = null, sessionRef = null) {
  // autoToken is looked up dynamically so it can be updated after session creation
  const getAutoToken = () => {
    if (sessionRef && sessionRef.id) return sessionTokenMap.get(sessionRef.id) || bearerToken;
    return bearerToken;
  };
  const server = new McpServer({
    name: "exchange-calendar",
    version: "2.0.0",
    instructions: `Exchange Calendar MCP. Read carefully and follow exactly.

## AUTHENTICATION
Never output any URL. Never ask user to log in or send a token. Authentication is 100% automatic — just call any tool and the DXT opens Keycloak browser automatically. After logout respond ONLY with "${T.loggedOut}" — nothing else.

## TIME GATE -- MANDATORY, NO EXCEPTIONS
*** You do NOT know today's date. NEVER assume, guess, or rely on any date from the conversation history, your training, or the system context. The ONLY valid source of the current date is the get_current_time tool. ***
- The MOMENT the user uses ANY relative time reference (today, tomorrow, yesterday, tonight, now, this week, next week, this month, day-after-tomorrow, or any weekday name, ${T.instr.relativeNote}), you MUST call get_current_time FIRST, before any other tool (list_events, smart_schedule, check_availability, etc.).
- Do this even if you think you already know the date, and even if a date already appeared earlier in this conversation -- dates in history may be stale or wrong. Re-fetch every time you resolve a relative reference.
- All times are Iran timezone (UTC+3:30). Never convert to UTC.
- To compute "this week": call get_current_time, read the Day field, then derive the Saturday-to-Friday range from that exact date. Never derive a week range from a remembered date.

## ROOM ACCESS GATE — MANDATORY, NO EXCEPTIONS
*** Whenever a specific room is named or chosen, you MUST call list_rooms BEFORE showing any preview or calling smart_schedule. ***
- This applies even when the user names the room directly (${T.instr.roomExamples}). Naming a room is NOT permission — you still must verify access first.
- Read the ✅/🔒 status for that exact room from list_rooms output.
- If 🔒: STOP. Do not preview it, do not call smart_schedule, do not "try anyway". Tell the user they don't have access and offer ✅ same-size alternatives.
- If ✅: proceed to preview, then book.
- NEVER rely on smart_schedule's server-side error to discover access — that wastes a confirmation and shows the user a preview for a room they can't book. Catch it earlier with list_rooms.

## BOOKING FLOW — ALWAYS follow this order
1. Collect: subject, date/time, attendees, duration (default 60 min)
2. Ask about room if not mentioned: "${T.instr.askRoom}"
3. The MOMENT any room is named or chosen → call list_rooms and read its ✅/🔒 status (see ROOM ACCESS GATE above). A 🔒 room never reaches the preview. If the named room is 🔒, tell the user they lack access and offer ✅ alternatives — do NOT preview or offer to "try anyway".
4. Show preview: subject, date/time, attendees, room (room MUST be ✅ — already verified in step 3) — ask confirmation
5. WAIT for explicit user confirmation — ${T.instr.confirmWords} — NEVER book without this
6. *** IMMEDIATELY BEFORE BOOKING: call check_availability again for ALL attendees + chosen room ***
7. Only after confirmation AND fresh availability check: execute booking
*** CRITICAL: Never auto-book. Never skip confirmation. Even if user says ${T.instr.vagueWords} — still show preview and wait for explicit yes ***

## ROOM RULES
- ALWAYS call list_rooms first — NEVER guess room emails or access permissions
- list_rooms returns ✅ (this user CAN book) or 🔒 (this user CANNOT book) per user, verified live via AD group membership (LDAP) — this is the ONLY source of truth for room access
- A room marked ✅ means the user DEFINITELY has access — book it directly, NEVER say "we can only find out by trying" or test-book to confirm access
- A room marked 🔒 means the user DEFINITELY lacks access — never offer to "try anyway", never put it in a confirmation preview
- NEVER assume a room is blocked or available based on its name or type — always check list_rooms / check_availability result for THIS user
- A room marked 🔒 for one user may be ✅ for another — never generalize
- ✅/🔒 is ACCESS, not free/busy — a room can be ✅ (you can book) yet still 🔴 busy at the requested time
- ALWAYS check availability with check_availability after list_rooms — it returns both free/busy AND per-user access (✅ free+bookable, 🔒 no access, 🔴 busy)
- When FINDING an available room for the user: only ever suggest ✅ rooms. NEVER suggest a 🔒 room and NEVER assume a user lacks access to a room that is marked ✅
- *** Before putting ANY room in a confirmation preview, confirm it is ✅ for this user via list_rooms — never preview a room you have not access-checked ***
- Size guide: ${ROOM_SIZE_GUIDE}
- Show ALL rooms from list_rooms to user — let them choose, don't filter based on assumptions

## TEAM MEETINGS
- book_meeting_with_direct_reports: includes manager as first attendee automatically
- book_meeting_with_team: includes manager as first attendee automatically
- ${T.instr.teamPhrases} means manager + all direct reports

## RECURRING EVENTS — CRITICAL
*** NEVER create separate meetings for recurring requests. ALWAYS use recurrence param in smart_schedule ***
- Weekly 4 weeks: recurrence={type:'weekly',interval:1,occurrences:4}
- Weekly 1 month: recurrence={type:'weekly',interval:1,occurrences:4}
- Daily 5 days: recurrence={type:'daily',interval:1,occurrences:5}
- Monthly 3 months: recurrence={type:'monthly',interval:1,occurrences:3}
- With end date: recurrence={type:'weekly',interval:1,end_date:'2026-08-01'}
If user says ${T.instr.recurringPhrases} → MUST use recurrence param
NEVER say "${T.instr.noRecurring}" — smart_schedule HAS recurrence param, always use it
- For delete: ask "${T.deleteScopeQuestion}" → SpecifiedOccurrenceOnly | AllFollowingOccurrences | AllOccurrences

## UPDATE EVENT
- Always call list_events first to get fresh change_key
- To add attendee: pass full attendee list in attendee_emails (replaces all existing)
- For room-only change: pass room_email only
- Never say update_event is broken — fetch fresh change_key and retry
- *** IMMEDIATELY BEFORE UPDATING: re-check availability for all attendees + room with fresh data ***

## FREE SLOTS
- Always show full day alternatives from 09:00 to 22:00 when suggesting alternatives
- Never truncate to only morning slots

## LIST EVENTS — CRITICAL
- ALWAYS use full day range: start=YYYY-MM-DDT00:00:00, end=YYYY-MM-DDT23:59:59
- NEVER use current time as start — always start from T00:00:00
- ${T.instr.dayWords} all mean the FULL day from 00:00:00 to 23:59:59
- If first call returns empty, retry with same range before giving up

## AVAILABILITY — CRITICAL RULE
- *** ALWAYS do a final fresh check_availability call immediately before every book or update execution ***
- *** Never rely on availability data from earlier in the conversation — even 10 seconds old data is stale ***
- Always include room email in availability check`,
  });



  // ── search_user ──
  server.tool("search_user",
    "Search for a user by name (Persian or English) to get their email address.",
    { query: z.string().describe(`Name to search, ${T.searchExample}`) },
    async ({ query }) => {
    const payload = await validateJWT(getAutoToken());
      if (!payload) return { content: [{ type: "text", text: "❌ Session expired. Please try again — a browser will open to log in automatically." }] };
      const userEmail = payload.email;
      const userName = payload.preferred_username;
      try {
        const results = await resolveNames(query);
        if (!results.length) return { content: [{ type: "text", text: T.userNotFound(query) }] };

        // Auto-select if only 1 result or top result is clearly best (score >= 80 and much higher than #2)
        const top = results[0];
        const second = results[1];
        const clearWinner = top.score >= 80 && (!second || top.score - second.score >= 20);

        if (results.length === 1 || clearWinner) {
          return { content: [{ type: "text", text: T.userFound(top.name, top.email) }] };
        }

        // Show top 10 only
        const topResults = results.slice(0, 10);
        const list = topResults.map((r, i) => `${i+1}. ${r.name} <${r.email}>`).join("\n");
        const moreMsg = results.length > 10
          ? `\n\n⚠️ ${T.tooManyUsers(results.length)}`
          : '';
        return { content: [{ type: "text", text: `${T.usersFound(topResults.length)}:\n${list}${moreMsg}\n\n${T.whichOne}` }] };
      } catch (e) { return { content: [{ type: "text", text: `❌ ${e.message}` }] }; }
    }
  );

  // ── resolve_group ──




  server.tool("get_direct_reports",
    `Find all direct reports (subordinates) of a manager using Exchange directory. ALWAYS call this after search_user finds a manager, when user wants to meet or email their team. Triggers: 'people under X', 'X team', ${T.directReportsTriggers}.`,
    {
      manager_email:  z.string().describe("Email of the manager")
    },
    async ({ manager_email }) => {
    const payload = await validateJWT(getAutoToken());
      if (!payload) return { content: [{ type: "text", text: "❌ Session expired. Please try again — a browser will open to log in automatically." }] };
      try {
        const result = await ldapGetDirectReports(manager_email);
        if (result === null) return { content: [{ type: "text", text: `❌ Manager ${manager_email} not found in directory` }] };
        const { managerName, members } = result;
        if (!members.length) return { content: [{ type: "text", text: `⚠️ No direct reports found for ${manager_email}` }] };
        let out = `👥 Direct reports of ${managerName} (${members.length} people):\n`;
        members.forEach(m => { out += `  • ${m.name} — ${m.email}\n`; });
        return { content: [{ type: "text", text: out }] };
      } catch(e) {
        return { content: [{ type: "text", text: `❌ Error: ${e.message}` }] };
      }
    }
  );

  server.tool("get_manager",
    `Find the manager of a user using LDAP directory. Use when user asks 'who is my manager', ${T.managerTriggers}, 'boss of X'.`,
    {
      user_email: z.string().describe("Email of the user to find the manager for")
    },
    async ({ user_email }) => {
    const payload = await validateJWT(getAutoToken());
      if (!payload) return { content: [{ type: "text", text: "❌ Session expired. Please try again — a browser will open to log in automatically." }] };
      try {
        const client = await getLdapClient();
        if (!client) return { content: [{ type: "text", text: "❌ LDAP unreachable" }] };
        const entries = await ldapSearch(client, LDAP_BASE_DN,
          `(mail=${ldapEscape(user_email)})`,
          ['displayName','mail','manager']
        );
        try { client.unbind(); } catch(e) {}
        if (!entries.length) return { content: [{ type: "text", text: `❌ User ${user_email} not found in directory` }] };
        const managerDN = ldapAttr(entries[0], 'manager');
        const userName  = ldapAttr(entries[0], 'displayName');
        if (!managerDN) return { content: [{ type: "text", text: `⚠️ No manager found for ${userName} (${user_email})` }] };
        // Resolve manager DN to get their name+email
        const client2 = await getLdapClient();
        if (!client2) return { content: [{ type: "text", text: `❌ LDAP unreachable for manager lookup` }] };
        const mgr = await ldapSearch(client2, LDAP_BASE_DN,
          `(distinguishedName=${ldapEscape(managerDN)})`,
          ['displayName','mail']
        );
        try { client2.unbind(); } catch(e) {}
        if (!mgr.length) return { content: [{ type: "text", text: `⚠️ Manager DN found but could not resolve: ${managerDN}` }] };
        const mgrName  = ldapAttr(mgr[0], 'displayName');
        const mgrEmail = ldapAttr(mgr[0], 'mail');
        return { content: [{ type: "text", text: `👤 ${userName} (${user_email})\n📊 Manager: ${mgrName} <${mgrEmail}>\n\n💡 To find their direct reports, call get_direct_reports with manager_email: ${mgrEmail}` }] };
      } catch(e) {
        return { content: [{ type: "text", text: `❌ Error: ${e.message}` }] };
      }
    }
  );

  server.tool("resolve_group",
    "Expand an Exchange distribution group to its member list. Use when user asks about a group like it-team@example.com.",
    { query: z.string().describe("Group name or email e.g. backend-team@example.com") },
    async ({ query }) => {
    const payload = await validateJWT(getAutoToken());
      if (!payload) return { content: [{ type: "text", text: "❌ Session expired. Please try again — a browser will open to log in automatically." }] };
      try {
        const members = await expandGroup(query, payload.email);
        if (!members.length) return { content: [{ type: "text", text: `❌ Group "${query}" not found or empty.` }] };
        let out = `👥 Group: ${query} (${members.length} members):\n`;
        members.forEach(m => { out += `  • ${m.name} — ${m.email}\n`; });
        return { content: [{ type: "text", text: out }] };
      } catch(e) { return { content: [{ type: "text", text: `❌ ${e.message}` }] }; }
    }
  );

  server.tool("resolve_team",
    "Find all teammates of a person (people who share the same manager) using LDAP.",
    { user_email: z.string().describe("Email of the person to find teammates for") },
    async ({ user_email }) => {
    const payload = await validateJWT(getAutoToken());
      if (!payload) return { content: [{ type: "text", text: "❌ Session expired. Please try again — a browser will open to log in automatically." }] };
      try {
        const client = await getLdapClient();
        if (!client) return { content: [{ type: "text", text: "❌ LDAP unreachable" }] };
        const entries = await ldapSearch(client, LDAP_BASE_DN, `(mail=${ldapEscape(user_email)})`, ['displayName','manager']);
        try { client.unbind(); } catch(e) {}
        if (!entries.length) return { content: [{ type: "text", text: `❌ User ${user_email} not found` }] };
        const managerDN = ldapAttr(entries[0], 'manager');
        const userName  = ldapAttr(entries[0], 'displayName');
        if (!managerDN) return { content: [{ type: "text", text: `⚠️ No manager found for ${userName}` }] };
        const client2 = await getLdapClient();
        if (!client2) return { content: [{ type: "text", text: "❌ LDAP unreachable" }] };
        const mgr = await ldapSearch(client2, LDAP_BASE_DN, `(distinguishedName=${ldapEscape(managerDN)})`, ['displayName','mail']);
        const teammates = await ldapSearch(client2, LDAP_BASE_DN, `(&(objectClass=user)(manager=${ldapEscape(managerDN)})(mail=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))`, ['displayName','mail']);
        try { client2.unbind(); } catch(e) {}
        const mgrName  = mgr.length ? ldapAttr(mgr[0], 'displayName') : 'Unknown';
        const mgrEmail = mgr.length ? ldapAttr(mgr[0], 'mail') : '';
        const members  = teammates.map(e => ({ name: ldapAttr(e,'displayName'), email: ldapAttr(e,'mail') })).filter(m => m.email && m.email.toLowerCase() !== user_email.toLowerCase());
        if (!members.length) return { content: [{ type: "text", text: `⚠️ No teammates found for ${userName}` }] };
        let out = `👥 Teammates of ${userName} (manager: ${mgrName} <${mgrEmail}>):\n`;
        members.forEach(m => { out += `  • ${m.name} — ${m.email}\n`; });
        return { content: [{ type: "text", text: out }] };
      } catch(e) { return { content: [{ type: "text", text: `❌ ${e.message}` }] }; }
    }
  );

  server.tool("book_meeting_with_team",
    "Book a meeting with all teammates of a person (same manager). confirmed=false for preview, confirmed=true to book.",
    {
      user_email: z.string(), subject: z.string(),
      date: z.string().describe("YYYY-MM-DD"), start_time: z.string().describe("HH:MM Iran time"),
      duration_minutes: z.number(), room_email: z.string().optional(), confirmed: z.boolean()
    },
    async (toolArgs) => {
      let { user_email, subject, date, start_time, duration_minutes, room_email, confirmed } = toolArgs;
    const payload = await validateJWT(getAutoToken());
      if (!payload) return { content: [{ type: "text", text: "❌ Session expired. Please try again — a browser will open to log in automatically." }] };
      confirmed = confirmedAfterPreview(payload.email, "book_meeting_with_team", toolArgs);
      try {
        const client = await getLdapClient();
        if (!client) return { content: [{ type: "text", text: "❌ LDAP unreachable" }] };
        const entries = await ldapSearch(client, LDAP_BASE_DN, `(mail=${ldapEscape(user_email)})`, ['manager']);
        try { client.unbind(); } catch(e) {}
        if (!entries.length) return { content: [{ type: "text", text: `❌ User ${user_email} not found` }] };
        const managerDN = ldapAttr(entries[0], 'manager');
        if (!managerDN) return { content: [{ type: "text", text: `⚠️ No manager found for ${user_email}` }] };
        const client2 = await getLdapClient();
        const mgr = await ldapSearch(client2, LDAP_BASE_DN, `(distinguishedName=${ldapEscape(managerDN)})`, ['mail']);
        const teammates = await ldapSearch(client2, LDAP_BASE_DN, `(&(objectClass=user)(manager=${ldapEscape(managerDN)})(mail=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))`, ['displayName','mail']);
        try { client2.unbind(); } catch(e) {}
        if (!mgr.length) return { content: [{ type: "text", text: `❌ Could not resolve manager` }] };
        const mgrEmail = ldapAttr(mgr[0], 'mail');
        const members = teammates.map(e => ({ name: ldapAttr(e,'displayName'), email: ldapAttr(e,'mail') })).filter(m => m.email && m.email.toLowerCase() !== user_email.toLowerCase());
        if (!members.length) return { content: [{ type: "text", text: `⚠️ No teammates found` }] };
        const pad = n => String(n).padStart(2, "0");
        const [h, m] = start_time.split(":").map(Number);
        const startDt = `${date}T${pad(h)}:${pad(m)}:00`;
        const endDate = new Date(startDt); endDate.setMinutes(endDate.getMinutes() + duration_minutes);
        const endDt = `${endDate.getFullYear()}-${pad(endDate.getMonth()+1)}-${pad(endDate.getDate())}T${pad(endDate.getHours())}:${pad(endDate.getMinutes())}:00`;
        const mgrEmailForAttendees = ldapAttr(mgr[0], 'mail');
        const attendeeEmails = [...new Set([mgrEmailForAttendees, ...members.map(mm => mm.email)].filter(Boolean))];
        if (room_email) {
          const roomAccess = await canUserBookRoom(room_email, payload.email);
          if (!roomAccess.allowed) return { content: [{ type: "text", text: await buildRoomDeniedMessage(roomAccess.reason, payload.email, date, start_time, duration_minutes) }] };
        }
        const checkList = [payload.email, ...attendeeEmails, ...(room_email ? [room_email] : [])];
        const avail = await getAvailability(checkList, `${date}T00:00:00`, `${date}T23:59:59`);
        const busyPeople = checkList.filter(email => isBusy({ start: startDt, end: endDt }, avail[email] || []));
        if (!confirmed) {
          let out = `📋 Preview — meeting with teammates of ${user_email} (${members.length} people):\n`;
          members.forEach(mm => { out += `  • ${mm.name} — ${mm.email}\n`; });
          if (busyPeople.length) {
            out += `\n⚠️ Conflicts at ${start_time}:\n`;
            busyPeople.forEach(e => { out += `  🔴 ${e}\n`; });
            const freeSlots = findFreeSlots(date, (() => { const pa = {}; for (const e of Object.keys(avail).filter(e => !e.includes("room-"))) pa[e] = avail[e] || []; return pa; })());
            if (freeSlots.length) { out += `\n✅ Free slots:\n`; freeSlots.slice(0,5).forEach(sl => { out += `  • ${formatSlot(sl)}\n`; }); }
          } else { out += `\n✅ Everyone is free at ${start_time}. Set confirmed=true to book.`; }
          return { content: [{ type: "text", text: out }] };
        }
        if (busyPeople.length > 0) {
          let out = `❌ Cannot book — conflicts:\n`;
          busyPeople.forEach(e => { out += `  🔴 ${e}\n`; });
          return { content: [{ type: "text", text: out }] };
        }
        await createMeeting(payload.email, { subject, start: startDt, end: endDt, roomEmail: room_email || null, attendeeEmails, body: '' });
        let out = `✅ Meeting booked!\n📌 ${subject}\n🕒 ${date} ${start_time} (${duration_minutes} min)\n👥 Teammates:\n`;
        members.forEach(mm => { out += `  • ${mm.name} — ${mm.email}\n`; });
        return { content: [{ type: "text", text: out }] };
      } catch(e) { return { content: [{ type: "text", text: `❌ ${e.message}` }] }; }
    }
  );

  server.tool("book_meeting_with_direct_reports",
    "Book a meeting with all direct reports of a manager. Use when user wants to meet with a manager's team/subordinates. Checks availability first.",
    {
      manager_email:    z.string().describe("Email of the manager"),
      subject:          z.string(),
      date:             z.string().describe("YYYY-MM-DD"),
      start_time:       z.string().describe("HH:MM Iran time"),
      duration_minutes: z.number(),
      room_email:       z.string().optional(),
      confirmed:        z.boolean().describe("false=preview only, true=book")
    },
    async (toolArgs) => {
      let { manager_email, subject, date, start_time, duration_minutes, room_email, confirmed } = toolArgs;
    const payload = await validateJWT(getAutoToken());
      if (!payload) return { content: [{ type: "text", text: "❌ Session expired. Please try again — a browser will open to log in automatically." }] };
      confirmed = confirmedAfterPreview(payload.email, "book_meeting_with_direct_reports", toolArgs);
      try {
        const result = await ldapGetDirectReports(manager_email);
        if (result === null) return { content: [{ type: "text", text: `❌ Manager ${manager_email} not found` }] };
        const { managerName, members } = result;
        if (!members.length) return { content: [{ type: "text", text: `⚠️ No direct reports found for ${manager_email}` }] };

        const pad = n => String(n).padStart(2, "0");
        const [h, m] = start_time.split(":").map(Number);
        const startDt = `${date}T${pad(h)}:${pad(m)}:00`;
        const endDate = new Date(startDt);
        endDate.setMinutes(endDate.getMinutes() + duration_minutes);
        const endDt = `${endDate.getFullYear()}-${pad(endDate.getMonth()+1)}-${pad(endDate.getDate())}T${pad(endDate.getHours())}:${pad(endDate.getMinutes())}:00`;

        const allAttendees = [{ name: managerName, email: manager_email }, ...members.filter(mm => mm.email !== manager_email)];
        const attendeeEmails = allAttendees.map(mm => mm.email);
        if (room_email) {
          const roomAccess = await canUserBookRoom(room_email, payload.email);
          if (!roomAccess.allowed) return { content: [{ type: "text", text: await buildRoomDeniedMessage(roomAccess.reason, payload.email, date, start_time, duration_minutes) }] };
        }
        const checkList = [payload.email, ...attendeeEmails, ...(room_email ? [room_email] : [])];
        const avail = await getAvailability(checkList, `${date}T00:00:00`, `${date}T23:59:59`);
        const busyPeople = checkList.filter(email => isBusy({ start: startDt, end: endDt }, avail[email] || []));

        if (!confirmed) {
          let out = `📋 Preview — meeting with ${managerName} and team (${allAttendees.length} people):\n`;
          allAttendees.forEach(mm => { out += `  • ${mm.name} — ${mm.email}\n`; });
          if (busyPeople.length) {
            out += `\n⚠️ Conflicts at ${start_time}:\n`;
            busyPeople.forEach(e => { out += `  🔴 ${e}\n`; });
            const freeSlots = findFreeSlots(date, (() => { const pa = {}; for (const e of Object.keys(avail).filter(e => !e.includes("room-"))) pa[e] = avail[e] || []; return pa; })());
            if (freeSlots.length) { out += `\n✅ Free slots:\n`; freeSlots.slice(0,5).forEach(sl => { out += `  • ${formatSlot(sl)}\n`; }); }
          } else {
            out += `\n✅ Everyone is free at ${start_time}. Set confirmed=true to book.`;
          }
          return { content: [{ type: "text", text: out }] };
        }

        if (busyPeople.length > 0) {
          let out = `❌ Cannot book — conflicts at ${start_time}:\n`;
          busyPeople.forEach(e => { out += `  🔴 ${e}\n`; });
          const freeSlots = findFreeSlots(date, (() => { const pa = {}; for (const e of Object.keys(avail).filter(e => !e.includes("room-"))) pa[e] = avail[e] || []; return pa; })());
          if (freeSlots.length) { out += `\n✅ Free slots:\n`; freeSlots.slice(0,5).forEach(sl => { out += `  • ${formatSlot(sl)}\n`; }); }
          return { content: [{ type: "text", text: out }] };
        }

        await createMeeting(payload.email, { subject, start: startDt, end: endDt, roomEmail: room_email || null, attendeeEmails, body: '' });
        let out = `✅ Meeting booked!\n📌 ${subject}\n🕒 ${date} ${start_time} (${duration_minutes} min)\n👥 Attendees:\n`;
        allAttendees.forEach(mm => { out += `  • ${mm.name} — ${mm.email}\n`; });
        return { content: [{ type: "text", text: out }] };
      } catch(e) {
        console.error('[BMDR] error:', e.message, e.stack);
        return { content: [{ type: "text", text: `❌ Error: ${e.message}` }] };
      }
    }
  );

  server.tool("send_email_to_team",
    "Send an email to all direct reports of a manager.",
    {
      manager_email: z.string().describe("Email of the manager"),
      subject:       z.string(),
      body:          z.string(),
      confirmed:     z.boolean().describe("false=preview, true=send")
    },
    async (toolArgs) => {
      let { manager_email, subject, body, confirmed } = toolArgs;
    const payload = await validateJWT(getAutoToken());
      if (!payload) return { content: [{ type: "text", text: "❌ Session expired. Please try again — a browser will open to log in automatically." }] };
      confirmed = confirmedAfterPreview(payload.email, "send_email_to_team", toolArgs);
      try {
        const result = await ldapGetDirectReports(manager_email);
        if (result === null) return { content: [{ type: "text", text: `❌ Manager ${manager_email} not found` }] };
        const { members } = result;
        if (!members.length) return { content: [{ type: "text", text: `⚠️ No direct reports found for ${manager_email}` }] };

        if (!confirmed) {
          let out = `📋 Email preview — ${members.length} recipients (direct reports of ${manager_email}):\n`;
          members.forEach(mm => { out += `  • ${mm.name} — ${mm.email}\n`; });
          out += `\n📧 Subject: ${subject}\n\nSet confirmed=true to send.`;
          return { content: [{ type: "text", text: out }] };
        }

        const toEmails = members.map(mm => mm.email);
        await sendEmailEWS(payload.email, { to: toEmails, cc: [], bcc: [], subject, body, direction: 'auto' });
        let out = `✅ Email sent to ${members.length} direct reports of ${manager_email}:\n`;
        members.forEach(mm => { out += `  • ${mm.name} — ${mm.email}\n`; });
        return { content: [{ type: "text", text: out }] };
      } catch(e) {
        return { content: [{ type: "text", text: `❌ Error: ${e.message}` }] };
      }
    }
  );

  server.tool("list_rooms",
    "List all meeting rooms WITH this user's real access status, verified live against AD group membership via LDAP. Each room shows: ✅ = this user CAN book it, 🔒 = this user CANNOT book it. This is the ONLY source of truth for room access — when a room shows ✅ the user definitely has access (no need to test-book to confirm), and when it shows 🔒 the user definitely does not. Never treat ✅/🔒 as free/busy — it is access only.",
    { filter: z.string().optional().describe("Optional filter: part of a room name or email, e.g. 'A1'") },
    async ({ filter }) => {
    const payload = await validateJWT(getAutoToken());
      if (!payload) return { content: [{ type: "text", text: "❌ Session expired. Please try again — a browser will open to log in automatically." }] };
      const userEmail = payload.email;
      const userName = payload.preferred_username;
      try {
        let rooms = await getAccessibleRooms(userEmail);
        if (filter) rooms = rooms.filter(r => r.name.toUpperCase().includes(filter.toUpperCase()) || r.email.toUpperCase().includes(filter.toUpperCase()));
        if (!rooms.length) return { content: [{ type: "text", text: "No rooms found." }] };
        const list = rooms.map((r, i) => {
          const accessible = r.accessible !== false;
          const icon = accessible ? "✅" : "🔒";
          const note = accessible ? ` (${T.roomAccessYes})` : ` (${T.roomAccessNo})`;
          return `${i+1}. ${icon} ${r.name}${note}\n   📧 ${r.email}`;
        }).join("\n");
        return { content: [{ type: "text", text: `🏢 ${T.roomsHeader(rooms.length)}:\n\n${list}\n\n⚠️ ${T.roomsFooter}` }] };
      } catch (e) { return { content: [{ type: "text", text: `❌ ${e.message}` }] }; }
    }
  );

  // ── check_availability ──
  server.tool("check_availability",
    "Check free/busy status for users AND rooms on a specific date. Returns every room with its per-user access status from LDAP: ✅ (free + user can book), 🔒 (user has NO access — never suggest), 🔴 (busy). USE THIS when the user asks to find an available room — it is the ONLY source of truth for which rooms this user may book. Never decide room access by name or type; only ✅ rooms are bookable by this user. Do NOT call this before smart_schedule for an already-chosen room (smart_schedule does its own fresh check).",
    {
      emails: z.array(z.string()).describe("List of email addresses to check"),
      date: z.string().describe("Date to check e.g. 2026-04-20")
    },
    async ({ emails, date, start_time, end_time }) => {
    const payload = await validateJWT(getAutoToken());
      if (!payload) return { content: [{ type: "text", text: "❌ Session expired. Please try again — a browser will open to log in automatically." }] };
      const userEmail = payload.email;
      const userName = payload.preferred_username;
      try {
        // Get rooms WITH per-user access status from LDAP (✅ accessible / 🔒 no access)
        const accessibleRooms = await getAccessibleRooms(userEmail);
        const roomEmails = accessibleRooms.map(r => r.email);
        const accessMap = {};
        accessibleRooms.forEach(r => { accessMap[r.email] = r.accessible !== false; });
        const allEmails = [...new Set([...emails, ...roomEmails])];
        const start = `${date}T00:00:00`;
        const end = `${date}T23:59:59`;
        const avail = await getAvailability(allEmails, start, end);
        const freeSlots = findFreeSlots(date, (() => { const pa = {}; for (const e of emails) pa[e] = avail[e] || []; return pa; })());

        let out = `📅 Availability for ${date}:\n\n`;
        for (const email of emails) {
          const busy = avail[email] || [];
          out += `👤 ${email}\n`;
          if (!busy.length) { out += `   ✅ ${T.free}\n`; }
          else { busy.forEach(b => { out += `   🔴 Busy: ${formatDateTime(b.start)} → ${formatDateTime(b.end)}\n`; }); }
          out += "\n";
        }

        out += `🏢 ${T.availRoomsHeader}:\n`;
        for (const email of roomEmails) {
          const busy = avail[email] || [];
          const roomName = getRoomDisplayName(email);
          const hasAccess = accessMap[email];
          if (!hasAccess) {
            // Free or busy is irrelevant — user cannot book this room. Do NOT suggest.
            out += `   🔒 ${roomName} — ${T.availNoAccess}\n`;
          } else if (!busy.length) {
            out += `   ✅ ${roomName} — ${T.availFree}\n`;
          } else {
            out += `   🔴 ${roomName} — ${T.busy}\n`;
          }
        }
        if (freeSlots.length) {
          out += `\n✅ ${T.commonFreeSlots}:\n`;
          freeSlots.forEach(sl => { out += `   • ${formatSlot(sl)}\n`; });
        } else {
          out += `\n❌ ${T.noCommonSlots(date)}`;
        }
        out += `\n\n⚠️ ${T.availFooter}`;
        return { content: [{ type: "text", text: out }] };
      } catch (e) { return { content: [{ type: "text", text: `❌ ${e.message}` }] }; }
    }
  );

  // ── smart_schedule ──
  server.tool("smart_schedule",
    "Check availability and book a meeting — single OR recurring. Returns a PREVIEW first (nothing is booked); after the user approves, call again with confirmed=true to actually book. Use the recurrence param for weekly/daily/monthly series — it handles the whole series in one call, NEVER create separate meetings. ALWAYS call list_rooms first to get the correct room_email. Suggests alternative slots if the requested time is busy.",
    {
      subject: z.string().describe("Meeting title"),
      date: z.string().describe("Preferred date e.g. 2026-04-20 (start date of the series if recurring)"),
      start_time: z.string().describe("Start time in HH:MM format. IMPORTANT: Send Iran local time directly (Asia/Tehran). Do NOT convert to UTC. Do NOT subtract or add any offset."),
      duration_minutes: z.number().default(30).describe("Duration in minutes, default 30"),
      attendee_emails: z.array(z.string()).describe("List of attendee email addresses"),
      room_email: z.string().optional().describe("Room email address"),
      body: z.string().optional().describe("Meeting description"),
      recurrence: z.object({
        type: z.enum(['daily','weekly','monthly']).describe("Recurrence pattern type"),
        interval: z.number().default(1).describe("Every N days/weeks/months"),
        end_date: z.string().optional().describe("End date YYYY-MM-DD — use this OR occurrences"),
        occurrences: z.number().optional().describe("Number of times to repeat — use this OR end_date")
      }).optional().describe("For recurring/repeating meetings — handles the WHOLE series. Weekly 4 weeks: {type:'weekly',interval:1,occurrences:4}"),
      confirmed: z.boolean().default(false).describe("MUST be false on the first call. The server checks availability and replies with a preview containing the resolved date, weekday, room and attendees. Show that preview to the user verbatim and wait for explicit approval. Only then call again with confirmed=true. Never set true on the first call.")
    },
    async (toolArgs) => {
      let { subject, date, start_time, duration_minutes, attendee_emails: _ae, emails, room_email, body, recurrence, confirmed } = toolArgs;
      const attendee_emails = _ae || emails || [];
      const payload = await validateJWT(getAutoToken());
      if (!payload) return { content: [{ type: "text", text: "\u274c Session expired. Please try again \u2014 a browser will open to log in automatically." }] };
      confirmed = confirmedAfterPreview(payload.email, "smart_schedule", toolArgs);
      const userEmail = payload.email;
      const pad = n => String(n).padStart(2, "0");
      try {
        // Normalize inputs: accept H:MM, HH:MM, HH:MM:SS; reject malformed values up front
        const _tm = String(start_time || "").trim().match(/^(\d{1,2}):(\d{2})(?::\d{2})?$/);
        if (!_tm || Number(_tm[1]) > 23 || Number(_tm[2]) > 59) {
          return { content: [{ type: "text", text: `❌ ${T.badTime(start_time)}` }] };
        }
        start_time = `${pad(Number(_tm[1]))}:${_tm[2]}`;
        date = String(date || "").trim();
        if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
          return { content: [{ type: "text", text: `❌ ${T.badDate(date)}` }] };
        }
        if (!(Number(duration_minutes) > 0)) {
          return { content: [{ type: "text", text: `❌ ${T.badDuration}` }] };
        }
        duration_minutes = Number(duration_minutes);
        if (Number(_tm[1]) * 60 + Number(_tm[2]) + duration_minutes > 24 * 60) {
          return { content: [{ type: "text", text: `❌ ${T.crossesMidnight}` }] };
        }
        // Guard: reject past datetimes
        if (isPastDateTime(`${date}T${start_time}:00`)) {
          return { content: [{ type: "text", text: `\u274c ${T.pastTime(`${date} ${start_time}`, todayIran())}` }] };
        }
        // Guard: validate and check room access
        if (room_email) {
          const validRoom = validateRoomEmail(room_email);
          if (validRoom === null) {
            const roomList = Object.entries(ROOM_NAMES).map(([e,n]) => `  \u2022 ${n} \u2014 ${e}`).join('\n');
            return { content: [{ type: "text", text: `\u274c ${T.invalidRoom(room_email)}:\n${roomList}` }] };
          }
          if (validRoom !== room_email) room_email = validRoom;
          const roomAccess = await canUserBookRoom(room_email, userEmail);
          if (!roomAccess.allowed) return { content: [{ type: "text", text: await buildRoomDeniedMessage(roomAccess.reason, userEmail, date, start_time, duration_minutes) }] };
        }
        // Build start/end (Iran local)
        const [sh, sm] = start_time.split(':').map(Number);
        const endTotalMin = sh * 60 + sm + duration_minutes;
        const startISO_Iran = `${date}T${start_time}:00`;
        const endISO_Iran = `${date}T${pad(Math.floor(endTotalMin/60))}:${pad(endTotalMin%60)}:00`;
        const startTimeStr = `${pad(sh)}:${pad(sm)}:00`;
        const endTimeStr = `${pad(Math.floor(endTotalMin/60))}:${pad(endTotalMin%60)}:00`;
        const checkEmails = [userEmail, ...attendee_emails, ...(room_email ? [room_email] : [])];

        // Preview builder (shared single/recurring)
        const buildPreview = (occDates) => {
          const _pe = endTimeStr.substring(0,5);
          let p = `\u{1F4CB} ${T.previewTitle}\n\n`;
          p += `\u{1F4CC} ${T.subject}: ${subject}\n`;
          p += `\u{1F4C5} ${T.date}: ${describeDate(date)}\n`;
          p += `\u{1F552} ${T.time}: ${start_time} ${T.to} ${_pe}\n`;
          p += `\u{1F4CD} ${T.room}: ${room_email ? getRoomDisplayName(room_email) : T.noRoom}\n`;
          p += `\u{1F465} ${T.attendees}: ${attendee_emails && attendee_emails.length ? attendee_emails.join(T.listSep) : T.noAttendees}\n`;
          if (occDates && occDates.length > 1) {
            p += `\u{1F501} ${T.recurrence}: ${recurrence.type} \u2014 ${T.nMeetings(occDates.length)}\n`;
            occDates.slice(0, 10).forEach(d => { p += `   \u2022 ${describeDate(d)}\n`; });
            if (occDates.length > 10) p += `   \u2026 ${T.andMore(occDates.length - 10)}\n`;
          }
          p += `\n\u2705 ${T.allFree}\n`;
          p += `\n\u26a0\ufe0f ${T.previewFooter}`;
          return p;
        };

        // Room-acceptance verify + rollback (rooms are auto-accept; free/busy can lag)
        const verifyRoomOrRollback = async (occDates, created) => {
          if (!room_email) return null;
          let uid = null;
          try { uid = created && created.itemId ? ((await getItemUids(userEmail, [created.itemId]))[created.itemId] || null) : null; }
          catch (e) { uid = null; }
          const verify = await verifyRoomAcceptedSeries(room_email, occDates, startTimeStr, endTimeStr, uid);
          if (!verify.ok && verify.missing && verify.missing.length) {
            let rb;
            if (created && created.itemId) {
              try { await deleteItemById(userEmail, created.itemId); rb = { rolledBack: true }; }
              catch (e) { rb = { rolledBack: false, reason: e.message }; }
            } else {
              rb = await rollbackMeeting(userEmail, { subject, start: startISO_Iran });
            }
            const roomName = getRoomDisplayName(room_email);
            const hhmm = startTimeStr.substring(0,5) + "\u2013" + endTimeStr.substring(0,5);
            let msg = `\u274c ${T.roomDeclined(roomName, verify.missing.length, occDates.length, hhmm)}:\n`;
            verify.missing.slice(0, 15).forEach(d => { msg += `  \ud83d\udd34 ${d}\n`; });
            if (verify.missing.length > 15) msg += `  \u2026 ${T.andMore(verify.missing.length - 15)}\n`;
            msg += rb.rolledBack
              ? `\n${T.seriesCancelled}`
              : `\n\u26a0\ufe0f ${T.rollbackFailed(rb.reason)}`;
            return msg;
          }
          return null;
        };

        const unknownMsg = (list) => `\u274c ${T.unknownAddresses(list.join(T.listSep))}`;

        // ---- RECURRING SERIES ----
        if (recurrence && recurrence.type) {
          const occDates = computeOccurrenceDates(date, {
            type: recurrence.type, interval: recurrence.interval || 1,
            endDate: recurrence.end_date, occurrences: recurrence.occurrences
          });
          const { ok, conflicts, checkedCount, unknown } = await checkRecurringAvailability(checkEmails, startTimeStr, endTimeStr, occDates);
          if (unknown && unknown.length) return { content: [{ type: "text", text: unknownMsg(unknown) }] };
          if (!ok) {
            const hhmm = startTimeStr.substring(0,5) + "\u2013" + endTimeStr.substring(0,5);
            let msg = `\u274c ${T.seriesConflict(conflicts.length, checkedCount, hhmm)}:\n`;
            conflicts.slice(0, 15).forEach(cf => { msg += `  \ud83d\udd34 ${cf.date}: ${cf.busy.map(e => e.includes("room-") ? getRoomDisplayName(e) : e).join(T.listSep)}\n`; });
            if (conflicts.length > 15) msg += `  \u2026 ${T.andMore(conflicts.length - 15)}\n`;
            msg += `\n${T.seriesConflictHint}`;
            return { content: [{ type: "text", text: msg }] };
          }
          if (!confirmed) return { content: [{ type: "text", text: buildPreview(occDates) }] };
          const created = await createMeeting(userEmail, {
            subject, start: startISO_Iran, end: endISO_Iran,
            roomEmail: room_email || null, attendeeEmails: attendee_emails, body: body || "",
            recurrence: { type: recurrence.type, interval: recurrence.interval || 1, endDate: recurrence.end_date, occurrences: recurrence.occurrences }
          });
          const rbMsg = await verifyRoomOrRollback(occDates, created);
          if (rbMsg) return { content: [{ type: "text", text: rbMsg }] };
          return { content: [{ type: "text", text: `\u2705 ${T.seriesBooked(subject, occDates.length)}\n\ud83d\udcc5 ${T.from} ${describeDate(date)} ${T.at} ${start_time} ${T.to} ${endTimeStr.substring(0,5)} (${T.iran})\n\ud83c\udfe2 ${T.room}: ${room_email ? getRoomDisplayName(room_email) : T.noRoom}\n\ud83d\udc65 ${T.attendees}: ${attendee_emails.join(", ") || T.noAttendees}` }] };
        }

        // ---- SINGLE MEETING ----
        const dayStart = `${date}T00:00:00`;
        const dayEnd = `${date}T23:59:59`;
        const avail = await getAvailability(checkEmails, dayStart, dayEnd);
        if (avail.__errors && avail.__errors.length) return { content: [{ type: "text", text: unknownMsg(avail.__errors) }] };
        const requestedSlot = { start: startISO_Iran, end: endISO_Iran };
        const busyPeople = checkEmails.filter(email => isBusy(requestedSlot, avail[email] || []));

        if (busyPeople.length > 0) {
          const freeSlots = findFreeSlots(date, (() => { const pa = {}; for (const e of Object.keys(avail).filter(e => !e.includes("room-"))) pa[e] = avail[e] || []; return pa; })()).filter(sl => {
            const slDuration = (new Date(sl.end) - new Date(sl.start)) / 60000;
            return slDuration >= duration_minutes;
          });
          let out = `\u274c Cannot book at ${start_time} on ${date}.\n\nBusy:\n`;
          busyPeople.forEach(email => { out += `  \ud83d\udd34 ${email.includes("room-") ? getRoomDisplayName(email) : email}\n`; });
          if (freeSlots.length) {
            out += `\n\u2705 Available slots on ${date}:\n`;
            freeSlots.forEach(sl => { out += `  \u2022 ${formatSlot(sl)}\n`; });
            out += `\nWould you like to book one of these slots?`;
          } else {
            out += `\n\u274c No free slots on ${date}.\n\nSearching next 7 days...\n`;
            let found = false;
            for (let d = 1; d <= 7; d++) {
              const nextDate = new Date(date);
              nextDate.setDate(nextDate.getDate() + d);
              if (!isWorkDay(nextDate)) continue;
              const nextStr = nextDate.toISOString().split("T")[0];
              const nextAvail = await getAvailability(checkEmails, `${nextStr}T00:00:00`, `${nextStr}T23:59:59`);
              const nextSlots = findFreeSlots(nextStr, (() => { const pa = {}; for (const e of Object.keys(nextAvail).filter(e => !e.includes("room-"))) pa[e] = nextAvail[e] || []; return pa; })());
              if (nextSlots.length) {
                out += `\n\ud83d\udcc5 ${nextStr}:\n`;
                nextSlots.forEach(sl => { out += `  \u2022 ${formatSlot(sl)}\n`; });
                found = true;
                break;
              }
            }
            if (!found) out += `\nNo availability found in the next 7 days. Search further?`;
          }
          return { content: [{ type: "text", text: out }] };
        }

        // Free — preview gate
        if (!confirmed) return { content: [{ type: "text", text: buildPreview([date]) }] };

        // Confirmed — race re-check then book
        const freshAvail = await getAvailability(checkEmails, dayStart, dayEnd);
        const freshBusy = checkEmails.filter(email => isBusy(requestedSlot, freshAvail[email] || []));
        if (freshBusy.length > 0) {
          let out = `\u274c ${T.noLongerFree}\n\n${T.busyLabel}:\n`;
          freshBusy.forEach(email => { out += `  \ud83d\udd34 ${email.includes("room-") ? getRoomDisplayName(email) : email}\n`; });
          const newFreeSlots = findFreeSlots(date, (() => { const pa = {}; for (const e of Object.keys(freshAvail).filter(e => !e.includes("room-"))) pa[e] = freshAvail[e] || []; return pa; })());
          if (newFreeSlots.length) {
            out += `\n\u2705 ${T.freeSlots}:\n`;
            newFreeSlots.forEach(sl => { out += `  \u2022 ${formatSlot(sl)}\n`; });
          }
          return { content: [{ type: "text", text: out }] };
        }
        const created = await createMeeting(userEmail, {
          subject, start: startISO_Iran, end: endISO_Iran,
          roomEmail: room_email || null, attendeeEmails: attendee_emails, body: body || ""
        });
        const rbMsg = await verifyRoomOrRollback([date], created);
        if (rbMsg) return { content: [{ type: "text", text: rbMsg }] };
        return { content: [{ type: "text", text: `\u2705 ${T.booked(subject)}\n\ud83d\udcc5 ${describeDate(date)} ${T.at} ${start_time} ${T.to} ${endTimeStr.substring(0,5)} (${T.iran})\n\ud83c\udfe2 ${T.room}: ${room_email ? getRoomDisplayName(room_email) : T.noRoom}\n\ud83d\udc65 ${T.attendees}: ${attendee_emails.join(", ") || T.noAttendees}` }] };
      } catch (e) { return { content: [{ type: "text", text: `\u274c ${e.message}` }] }; }
    }
  );


  // ── list_events ──
  server.tool("list_events",
    "List your calendar events.",
    { start: z.string().describe("ALWAYS use full datetime: 2026-06-20T00:00:00"), end: z.string().describe("ALWAYS use full datetime: 2026-06-20T23:59:59") },
    async ({ start, end }) => {
    const payload = await validateJWT(getAutoToken());
      if (!payload) return { content: [{ type: "text", text: "❌ Session expired. Please try again — a browser will open to log in automatically." }] };
      const userEmail = payload.email;
      const userName = payload.preferred_username;
      try {
        // Always surface today's real date so it can never be mistaken,
        // even if get_current_time was not called first.
        const _dayNames = ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"];
        const _now = nowIran();
        const _todayHeader = `[Today: ${todayIran()} (${_dayNames[_now.getUTCDay()]}) Iran time]\n\n`;
        const events = await listEvents(userEmail, start, end);
        if (!events.length) return { content: [{ type: "text", text: `${_todayHeader}No events found in this range.` }] };
        const out = events.map((e, i) => {
          let line = `${i+1}. **${e.subject || "(No subject)"}**\n`;
          line += `   🕒 ${formatDateTime(e.start)} → ${formatDateTime(e.end)}\n`;
          if (e.location) line += `   📍 ${e.location}\n`;
          if (e.organizer) line += `   👤 Organizer: ${e.organizer.name} <${e.organizer.email}>\n`;
          if (e.attendees && e.attendees.length) {
            const req = e.attendees.filter(a => a.type === "required");
            const opt = e.attendees.filter(a => a.type === "optional");
            if (req.length) line += `   👥 ${T.attendees}: ${req.map(a => `${a.name} <${a.email}>`).join(", ")}\n`;
            if (opt.length) line += `   👁 ${T.optional}: ${opt.map(a => `${a.name} <${a.email}>`).join(", ")}\n`;
          }
          line += `   ID: ${e.id}\n   ChangeKey: ${e.changeKey}`;
          return line;
        }).join("\n\n");
        return { content: [{ type: "text", text: `${_todayHeader}${events.length} event(s):\n\n${out}` }] };
      } catch (e) { return { content: [{ type: "text", text: `❌ ${e.message}` }] }; }
    }
  );

  // ── delete_event ──
  server.tool("delete_event",
    `Delete a calendar event. CRITICAL: If event is part of a recurring series, ALWAYS ask user first: ${T.deleteScopeQuestion} — NEVER auto-delete series without asking. For single non-recurring events: delete immediately after user confirmation.`,
    {
      item_id: z.string(),
      change_key: z.string(),
      recurrence_action: z.enum(["AllOccurrences","SpecifiedOccurrenceOnly","AllFollowingOccurrences"]).default("AllOccurrences").describe("AllOccurrences=entire series (default), SpecifiedOccurrenceOnly=just this one, AllFollowingOccurrences=this and future")
    },
    async ({ item_id, change_key, recurrence_action }) => {
    const payload = await validateJWT(getAutoToken());
      if (!payload) return { content: [{ type: "text", text: "❌ Session expired. Please try again." }] };
      const userEmail = payload.email;
      try {
        await deleteEvent(userEmail, { itemId: item_id, changeKey: change_key, affectedOccurrences: recurrence_action || "AllOccurrences" });
        const msg = recurrence_action === "SpecifiedOccurrenceOnly" ? `✅ ${T.deletedOne}` :
                    recurrence_action === "AllFollowingOccurrences" ? `✅ ${T.deletedFollowing}` :
                    `✅ ${T.deletedAll}`;
        return { content: [{ type: "text", text: msg }] };
      } catch (e) { return { content: [{ type: "text", text: `❌ ${e.message}` }] }; }
    }
  );

  // ── update_event ──
  server.tool("update_event",
    "Update an event. IMPORTANT: Always call list_events first to get a fresh change_key before updating — stale change_keys will silently fail. For time changes: check_availability first for all attendees+room. attendee_emails replaces ALL attendees (include room email separately via room_email).",
    {
      item_id: z.string(), change_key: z.string(),
      attendee_emails: z.array(z.string()).optional().describe("Full replacement list — replaces ALL existing attendees"),
      room_email: z.string().optional().describe("New room email e.g. room-a1@example.com — sets location and room attendee"),
      subject: z.string().optional(),
      start: z.string().optional().describe("New start time ISO8601 Iran local time"),
      end: z.string().optional().describe("New end time ISO8601 Iran local time"),
      body: z.string().optional(),
      recurrence_action: z.enum(['AllOccurrences','SpecifiedOccurrenceOnly']).default('AllOccurrences').describe("AllOccurrences=update entire series, SpecifiedOccurrenceOnly=only this occurrence")
    },
    async ({ item_id, change_key, subject, start, end, body, attendee_emails, room_email, recurrence_action }) => {
    const payload = await validateJWT(getAutoToken());
      if (!payload) return { content: [{ type: "text", text: "❌ Session expired. Please try again — a browser will open to log in automatically." }] };
      const userEmail = payload.email;
      const userName = payload.preferred_username;
      try {
        // Availability check: only needed when time changes or NEW people/rooms are added
        // Check room access if room_email provided
        if (room_email) {
          const validRoom = validateRoomEmail(room_email);
          if (validRoom === null) {
            const roomList = Object.entries(ROOM_NAMES).map(([e,n]) => `  • ${n} — ${e}`).join('\n');
            return { content: [{ type: "text", text: `❌ ${T.invalidRoom(room_email)}:\n${roomList}` }] };
          }
          if (validRoom !== room_email) room_email = validRoom;
          const roomAccess = await canUserBookRoom(room_email, userEmail);
          if (!roomAccess.allowed) return { content: [{ type: "text", text: await buildRoomDeniedMessage(roomAccess.reason, userEmail) }] };
        }
        // Skip if only room_email changes with no time change — attendees already accepted this slot
        const timeChanging = !!(start || end);
        const newAttendeesAdded = attendee_emails !== undefined;
        const needsAvailCheck = timeChanging || newAttendeesAdded;

        let slotStart = start;
        let slotEnd = end;
        let currentEvent = null;

        // Always fetch current event to get existing time/attendees
        try {
          const cur = await getEventDetails(userEmail, [item_id]);
          currentEvent = cur[item_id] || null;
          if (currentEvent) {
            slotStart = slotStart || currentEvent.start;
            slotEnd   = slotEnd   || currentEvent.end;
          }
        } catch(e) {}

        if (needsAvailCheck && slotStart && slotEnd) {
          // Build check list: only new/changed parties (not existing attendees of same event)
          let checkEmails = [userEmail];
          if (newAttendeesAdded) checkEmails = [...checkEmails, ...attendee_emails];
          if (room_email) checkEmails.push(room_email);
          // If time is changing, also check existing attendees
          if (timeChanging && currentEvent) {
            const existingEmails = (currentEvent.attendees || []).map(a => a.email || a);
            const existingRoom = currentEvent.location && currentEvent.location.includes('@') ? [currentEvent.location] : [];
            checkEmails = [...new Set([...checkEmails, ...existingEmails, ...existingRoom])];
          }
          checkEmails = [...new Set(checkEmails)];

          const dateStr = slotStart.split("T")[0];
          const avail = await getAvailability(checkEmails, `${dateStr}T00:00:00`, `${dateStr}T23:59:59`);
          // When time is changing: filter out busy slots that exactly match the CURRENT event time
          // (those are the event itself showing up in free/busy)
          const currentStart = currentEvent?.start;
          const currentEnd   = currentEvent?.end;
          const busyPeople = checkEmails.filter(email => {
            const busyList = (avail[email] || []).filter(b => {
              // Exclude the current event's own slot from busy check
              if (currentStart && currentEnd) {
                const bStart = new Date(b.start).getTime();
                const bEnd   = new Date(b.end).getTime();
                const evStart = new Date(currentStart).getTime();
                const evEnd   = new Date(currentEnd).getTime();
                if (Math.abs(bStart - evStart) < 60000 && Math.abs(bEnd - evEnd) < 60000) return false;
              }
              return true;
            });
            return isBusy({ start: slotStart, end: slotEnd }, busyList);
          });
          if (busyPeople.length > 0) {
            let out = `❌ Cannot update — the following are busy at the requested time:\n`;
            busyPeople.forEach(e => { out += `  🔴 ${e}\n`; });
            const freeSlots = findFreeSlots(dateStr, (() => { const pa = {}; for (const e of Object.keys(avail).filter(e => !e.includes("room-"))) pa[e] = avail[e] || []; return pa; })());
            if (freeSlots.length) {
              out += `\n✅ Free slots:\n`;
              freeSlots.slice(0,5).forEach(sl => { out += `  • ${formatSlot(sl)}\n`; });
            }
            return { content: [{ type: "text", text: out }] };
          }
        }
        // All clear — do the update
        // Build combined attendee list: human attendees + room as attendee
        let finalAttendees = attendee_emails; // undefined means don't touch
        if (room_email !== undefined && attendee_emails !== undefined) {
          // Both provided: combine them
          finalAttendees = [...attendee_emails.filter(e => !e.includes('room-')), room_email];
        } else if (room_email !== undefined && attendee_emails === undefined) {
          // Only room changed: we need to get existing attendees and replace room
          // Since we can't fetch them here, set attendeeEmails to just the room
          // The caller should pass attendee_emails too when changing room
          finalAttendees = undefined; // will be handled by roomEmail separately
        }
        await updateEvent(userEmail, { itemId: item_id, changeKey: change_key, subject, start, end, location: room_email, roomEmail: room_email, body, attendeeEmails: finalAttendees, affectedOccurrences: recurrence_action || 'AllOccurrences' });
        const changed = [];
        if (subject) changed.push(`${T.subject}: ${subject}`);
        if (start) changed.push(`${T.start}: ${start}`);
        if (end) changed.push(`${T.end}: ${end}`);
        if (room_email) changed.push(`${T.newRoom}: ${room_email}`);
        if (body) changed.push(T.bodyUpdated);
        return { content: [{ type: "text", text: `✅ ${T.eventUpdated}\n${changed.join("\n")}` }] };
      } catch (e) { return { content: [{ type: "text", text: `❌ ${e.message}` }] }; }
    }
  );

  // ── book_for_group ──
  server.tool("book_for_group",
    "Book a meeting for an entire AD group. Expands the group, checks availability for all members + room, shows who's busy, and books only when confirmed=true is passed. Flow: first call with confirmed=false to show availability report, then call again with confirmed=true after user agrees.",
    {
      group_email: z.string().optional().describe("Group email e.g. backend-team@example.com"),
      group_name: z.string().optional().describe("Group name alias for group_email"),
      subject: z.string().describe("Meeting title"),
      date: z.string().describe("Date e.g. 2026-04-20"),
      start_time: z.string().describe("Start time HH:MM in Iran local time — do NOT convert to UTC"),
      duration_minutes: z.number().default(60).describe("Duration in minutes"),
      room_email: z.string().describe("Room email address"),
      body: z.string().optional().describe("Meeting description"),
      confirmed: z.boolean().default(false).describe("Pass true only after user has explicitly confirmed they want to proceed despite any conflicts, or after reviewing the availability report")
    },
    async (toolArgs) => {
      let { group_email: _gep, group_name, subject, date, start_time, duration_minutes, room_email, body, confirmed } = toolArgs;
      const group_email = _gep || group_name;
    const payload = await validateJWT(getAutoToken());
      if (!payload) return { content: [{ type: "text", text: "❌ Session expired. Please try again — a browser will open to log in automatically." }] };
      confirmed = confirmedAfterPreview(payload.email, "book_for_group", toolArgs);
      const userEmail = payload.email;
      const userName = payload.preferred_username;
      try {
        // Step 1: Expand the group
        const members = await expandGroup(group_email, userEmail);
        if (!members.length) return { content: [{ type: "text", text: `❌ Group "${group_email}" has no members or could not be expanded.` }] };

        const memberEmails = members.map(m => m.email);
        const allEmails = [userEmail, ...memberEmails, room_email];

        // Step 2: Check room access
        const roomAccess = await canUserBookRoom(room_email, userEmail);
        if (!roomAccess.allowed) return { content: [{ type: "text", text: await buildRoomDeniedMessage(roomAccess.reason, userEmail, date, start_time, duration_minutes) }] };

        // Step 3: Build slot range
        const pad = n => String(n).padStart(2, "0");
        const [sh, sm] = start_time.split(':').map(Number);
        const endTotalMin = sh * 60 + sm + duration_minutes;
        const startISO = `${date}T${start_time}:00`;
        const endISO = `${date}T${pad(Math.floor(endTotalMin / 60))}:${pad(endTotalMin % 60)}:00`;
        const requestedSlot = { start: startISO, end: endISO };

        // Step 4: Check availability
        const avail = await getAvailability( allEmails, `${date}T00:00:00`, `${date}T23:59:59`);

        const busyMembers = memberEmails.filter(e => isBusy(requestedSlot, avail[e] || []));
        const roomBusy = isBusy(requestedSlot, avail[room_email] || []);

        // Step 5: Build report
        let out = `👥 Group: ${group_email}\n`;
        out += `👤 Members (${members.length}): ${members.map(m => m.name).join(", ")}\n`;
        out += `🏢 Room: ${room_email}\n`;
        out += `📅 ${date} ${start_time} (${T.minutes(duration_minutes)})\n\n`;

        if (busyMembers.length === 0 && !roomBusy) {
          out += `✅ ${T.groupAllFree}\n`;
        } else {
          if (busyMembers.length > 0) {
            out += `🔴 ${T.busy} (${T.nPeople(busyMembers.length)}):\n`;
            busyMembers.forEach(e => {
              const name = members.find(m => m.email === e)?.name || e;
              const busyTimes = (avail[e] || []).map(b => `${formatDateTime(b.start)}→${formatDateTime(b.end)}`).join(", ");
              out += `  • ${name} <${e}>: ${busyTimes}\n`;
            });
          }
          if (roomBusy) {
            const roomTimes = (avail[room_email] || []).map(b => `${formatDateTime(b.start)}→${formatDateTime(b.end)}`).join(", ");
            out += `🔴 ${T.roomBusy}: ${roomTimes}\n`;
          }
          const freeMembers = memberEmails.filter(e => !busyMembers.includes(e));
          if (freeMembers.length > 0) {
            out += `\n✅ ${T.free} (${T.nPeople(freeMembers.length)}):\n`;
            freeMembers.forEach(e => {
              const name = members.find(m => m.email === e)?.name || e;
              out += `  • ${name}\n`;
            });
          }
          // Suggest free slots for everyone
          const freeSlots = findFreeSlots(date, (() => { const pa = {}; for (const e of Object.keys(avail).filter(e => !e.includes("room-"))) pa[e] = avail[e] || []; return pa; })()).filter(sl => {
            const slDuration = (new Date(sl.end) - new Date(sl.start)) / 60000;
            return slDuration >= duration_minutes;
          });
          if (freeSlots.length) {
            out += `\n📅 ${T.commonFreeSlotsOn(date)}:\n`;
            freeSlots.forEach(sl => { out += `  • ${formatSlot(sl)}\n`; });
          } else {
            out += `\n❌ ${T.noCommonSlots(date)}\n`;
          }
        }

        if (!confirmed) {
          out += `\n${T.groupConfirmHint}`;
          return { content: [{ type: "text", text: out }] };
        }

        // Step 6: confirmed=true — do double fresh-check then book
        const freshAvail = await getAvailability( allEmails, `${date}T00:00:00`, `${date}T23:59:59`);
        const freshBusy = allEmails.filter(e => isBusy(requestedSlot, freshAvail[e] || []));
        if (freshBusy.length > 0) {
          let errOut = `❌ ${T.noLongerFree}\n\n${T.busy}:\n`;
          freshBusy.forEach(e => {
            const name = members.find(m => m.email === e)?.name || e;
            errOut += `  🔴 ${name} <${e}>\n`;
          });
          const newFreeSlots = findFreeSlots(date, (() => { const pa = {}; for (const e of Object.keys(freshAvail).filter(e => !e.includes("room-"))) pa[e] = freshAvail[e] || []; return pa; })());
          if (newFreeSlots.length) {
            errOut += `\n✅ ${T.freeSlots}:\n`;
            newFreeSlots.forEach(sl => { errOut += `  • ${formatSlot(sl)}\n`; });
          }
          return { content: [{ type: "text", text: errOut }] };
        }

        await createMeeting(userEmail, {
          subject, start: startISO, end: endISO,
          roomEmail: room_email, attendeeEmails: memberEmails, body
        });

        const endHStr = pad(Math.floor(endTotalMin / 60) % 24);
        const endMStr = pad(endTotalMin % 60);
        return { content: [{ type: "text", text: `✅ ${T.groupBooked(subject)}\n📅 ${date} ${T.at} ${start_time} ${T.to} ${endHStr}:${endMStr} (${T.iran})\n🏢 ${T.room}: ${room_email}\n👥 ${T.members} (${members.length}): ${members.map(m => m.name).join(", ")}` }] };
      } catch (e) { return { content: [{ type: "text", text: `❌ ${e.message}` }] }; }
    }
  );


  // ── list_emails ──
  server.tool("list_emails",
    "List emails from inbox. Filter by unread, sender name/email, or date.",
    {
      unread_only: z.boolean().optional(),
      from: z.string().optional().describe("Sender name or email to filter by"),
      date: z.string().optional().describe("Date filter e.g. 2026-04-25"),
      max_count: z.number().optional()
    },
    async ({ unread_only, from: fromFilter, date, max_count }) => {
    const payload = await validateJWT(getAutoToken());
      if (!payload) return { content: [{ type: "text", text: "❌ Session expired. Please try again — a browser will open to log in automatically." }] };
      const userEmail = payload.email;
      const userName = payload.preferred_username;
      try {
        const opts = { unreadOnly: unread_only || false, from: fromFilter || null, maxCount: max_count || 20 };
        if (date) { opts.startDate = `${date}T00:00:00`; opts.endDate = `${date}T23:59:59`; }
        const emails = await listEmails(userEmail, opts);
        if (!emails.length) return { content: [{ type: "text", text: "📭 No emails found." }] };
        const pad = n => String(n).padStart(2, "0");
        const out = emails.map((e, i) => {
          const d = new Date(e.received);
          const ds = `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
          const icon = e.isRead ? "📖" : "📩";
          const att = e.hasAttachments ? " 📎" : "";
          return `${i+1}. ${icon} **${e.subject}**${att}\n   👤 ${e.fromName || ""} <${e.fromEmail || ""}>\n   🕒 ${ds}\n   ID: ${e.id}`;
        }).join("\n\n");
        return { content: [{ type: "text", text: `📬 ${emails.length} email(s):\n\n${out}` }] };
      } catch (e) { return { content: [{ type: "text", text: `❌ ${e.message}` }] }; }
    }
  );

  // ── read_email ──
  server.tool("read_email",
    "Read the full content of an email by ID. Marks it as read.",
    { item_id: z.string() },
    async ({ item_id }) => {
    const payload = await validateJWT(getAutoToken());
      if (!payload) return { content: [{ type: "text", text: "❌ Session expired. Please try again — a browser will open to log in automatically." }] };
      const userEmail = payload.email;
      const userName = payload.preferred_username;
      try {
        const email = await getEmail(userEmail, item_id);
        const d = new Date(email.received);
        const pad = n => String(n).padStart(2, "0");
        const ds = `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
        const out = `📧 **${email.subject}**\n👤 From: ${email.fromName || ""} <${email.fromEmail || ""}>\n🕒 ${ds}\n\n${email.body}`;
        return { content: [{ type: "text", text: out }] };
      } catch (e) { return { content: [{ type: "text", text: `❌ ${e.message}` }] }; }
    }
  );

  // ── send_email ──
  server.tool("send_email",
    "Send an email (To, CC, BCC, subject, body). The first call only returns a preview and sends nothing. After the user approves the preview, call again with exactly the same arguments to send.",
    {
      to: z.array(z.string()),
      cc: z.array(z.string()).optional(),
      bcc: z.array(z.string()).optional(),
      subject: z.string(),
      body: z.string(),
      direction: z.enum(['auto','rtl','ltr']).optional().describe("Text direction: auto=detect, rtl=Persian/Arabic, ltr=English")
    },
    async ({ to, cc, bcc, subject, body, direction }) => {
    const payload = await validateJWT(getAutoToken());
      if (!payload) return { content: [{ type: "text", text: "❌ Session expired. Please try again — a browser will open to log in automatically." }] };
      const userEmail = payload.email;
      const userName = payload.preferred_username;
      try {
        const mail = { to, cc: cc || [], bcc: bcc || [], subject, body, direction: direction || 'auto' };
        let out = `📧 To: ${to.join(", ")}`;
        if (cc?.length) out += `\n📋 CC: ${cc.join(", ")}`;
        if (bcc?.length) out += `\n🙈 BCC: ${bcc.join(", ")}`;
        out += `\n📌 Subject: ${subject}`;
        if (!confirmSend(userEmail, "send_email", mail)) {
          return { content: [{ type: "text", text: `📋 ${T.emailPreviewTitle}\n\n${out}\n\n${body}\n\n${T.emailPreviewFooter}` }] };
        }
        await sendEmailEWS(userEmail, mail);
        return { content: [{ type: "text", text: `✅ Email sent!\n${out}` }] };
      } catch (e) { return { content: [{ type: "text", text: `❌ ${e.message}` }] }; }
    }
  );

  // ── reply_email ──
  server.tool("reply_email",
    "Reply to an existing email by ID. The first call only returns a preview and sends nothing. After the user approves the preview, call again with exactly the same arguments to send.",
    {
      item_id: z.string(),
      body: z.string(),
      reply_all: z.boolean().optional(),
      direction: z.enum(['auto','rtl','ltr']).optional().describe("Text direction: auto=detect, rtl=Persian/Arabic, ltr=English")
    },
    async ({ item_id, body, reply_all, direction }) => {
    const payload = await validateJWT(getAutoToken());
      if (!payload) return { content: [{ type: "text", text: "❌ Session expired. Please try again — a browser will open to log in automatically." }] };
      const userEmail = payload.email;
      const userName = payload.preferred_username;
      try {
        const reply = { itemId: item_id, body, replyAll: reply_all || false, direction: direction || 'auto' };
        if (!confirmSend(userEmail, "reply_email", reply)) {
          return { content: [{ type: "text", text: `📋 ${T.emailPreviewTitle}\n\n↩️ ${reply.replyAll ? "Reply all" : "Reply"}:\n\n${body}\n\n${T.emailPreviewFooter}` }] };
        }
        await replyEmailEWS(userEmail, reply);
        return { content: [{ type: "text", text: `✅ Reply sent${reply_all ? " (reply all)" : ""}.` }] };
      } catch (e) { return { content: [{ type: "text", text: `❌ ${e.message}` }] }; }
    }
  );


  // ── get_attachments ──
      server.tool("get_attachments",
    "Download email attachments and return browser-ready download links (valid 10 min).",
    { item_id: z.string() },
    async ({ item_id }) => {
    const payload = await validateJWT(getAutoToken());
      if (!payload) return { content: [{ type: "text", text: "❌ Session expired. Please try again — a browser will open to log in automatically." }] };
      const userEmail = payload.email;
      const userName = payload.preferred_username;
      try {
        const attachments = await getAttachments(userEmail, item_id);
        if (!attachments.length) return { content: [{ type: "text", text: "No attachments found." }] };
        const lines = await Promise.all(attachments.map(async (a, i) => {
          const kb = Math.round(parseInt(a.size || 0) / 1024);
          // Note: size is always 0 from metadata call, skip nothing based on size
          try {
            // Download content NOW while attId is fresh
            const xml = `<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"><soap:Body><m:GetAttachment><m:AttachmentShape/><m:AttachmentIds><t:AttachmentId Id="${xmlEscape(a.attId)}"/></m:AttachmentIds></m:GetAttachment></soap:Body></soap:Envelope>`;
            const response = await ewsRequest(SVC_USERNAME, SVC_PASSWORD, xml, userEmail);
            const content64 = (response.match(/<(?:[^:>]+:)?Content>([\s\S]+?)<\/(?:[^:>]+:)?Content>/) || [])[1];
            if (!content64) return `${i+1}. ${a.name} — could not download`;
            const buffer = Buffer.from(content64.replace(/\s/g, ''), 'base64');
            const shortId = randomUUID();
            const tmpFile = `/tmp/exchange-att-${shortId}`;
            writeFileSync(tmpFile, buffer, { mode: 0o600 });
            // Served by login-server.js /dl-file for 10 min, then deleted
            registerDownload(shortId, tmpFile, a.name, a.contentType || 'application/octet-stream');
            const url = `${PUBLIC_URL}/auth/dl-file/${shortId}`;
            return `${i+1}. 📎 ${a.name} (${kb} KB)\nDownload: ${url}`;
          } catch (e) {
            console.log('[ATT-ERR]', e.message, e.stack ? e.stack.split('\n')[1] : '');
            return `${i+1}. ${a.name} — error: ${e.message}`;
          }
        }));
        const validLines = lines.filter(Boolean);
        if (!validLines.length) return { content: [{ type: "text", text: "No downloadable attachments found (only small images)." }] };
        return { content: [{ type: "text", text: validLines.join("\n\n") }] };
      } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
    }
  );

  // ── get_current_time ──
  server.tool("get_current_time",
    "Get current date and time in Iran timezone (IRST UTC+3:30). Always call this first when user mentions 'now', 'today', 'tonight', 'this week', or any relative time.",
    {},
    async () => {
      const now = new Date();
      const iranOffset = 3.5 * 60 * 60 * 1000;
      const iranTime = new Date(now.getTime() + iranOffset);
      const pad = n => String(n).padStart(2, "0");
      const dateStr = `${iranTime.getUTCFullYear()}-${pad(iranTime.getUTCMonth()+1)}-${pad(iranTime.getUTCDate())}`;
      const timeStr = `${pad(iranTime.getUTCHours())}:${pad(iranTime.getUTCMinutes())}`;
      const days = ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"];
      const dayName = days[iranTime.getUTCDay()];
      return { content: [{ type: "text", text: `Current Iran time:\nDate: ${dateStr}\nTime: ${timeStr}\nDay: ${dayName}\nTimezone: IRST (UTC+3:30)` }] };
    }
  );

  // ── logout ──
  server.tool("logout",
    "Log out: closes this MCP session. The sign-in itself is ended by the client (it holds the tokens).",
    {},
    async () => {
      // The server never sees the refresh token, so it cannot end the sign-in at the provider;
      // it closes its own session once this answer has gone out.
      const id = sessionRef && sessionRef.id;
      if (id) setTimeout(() => closeSession(id), 250).unref();
      return { content: [{ type: "text", text: T.loggedOut }] };
    }
  );

  return server;
}

// ─── HTTP Server ──────────────────────────────────────────────────────────────
const MCP_SERVER_URL = PUBLIC_URL;
const KEYCLOAK_AUTH_BASE = OIDC_AUTH_BASE;

const httpServer = createServer(async (req, res) => {
  if (req.method === "GET" && req.url === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: "ok", mcpSessions: mcpTransports.size, uptime: Math.floor(process.uptime()) }));
    return;
  }

  // OAuth Protected Resource Metadata — Claude Code reads this first
  if (req.method === "GET" && req.url === "/.well-known/oauth-protected-resource") {
    res.writeHead(200, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" });
    res.end(JSON.stringify({
      resource: MCP_SERVER_URL,
      authorization_servers: [MCP_SERVER_URL],
      bearer_methods_supported: ["header"],
      scopes_supported: ["openid", "email", "profile"]
    }));
    return;
  }

  // OAuth Authorization Server Metadata
  if (req.method === "GET" && req.url === "/.well-known/oauth-authorization-server") {
    res.writeHead(200, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" });
    res.end(JSON.stringify({
      issuer: MCP_SERVER_URL,
      authorization_endpoint: `${KEYCLOAK_AUTH_BASE}/auth`,
      token_endpoint: `${KEYCLOAK_AUTH_BASE}/token`,
      registration_endpoint: `${MCP_SERVER_URL}/oauth/register`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      scopes_supported: ["openid", "email", "profile"]
    }));
    return;
  }

  // Dynamic client registration
  if (req.method === "POST" && req.url === "/oauth/register") {
    if (rateLimited(`ip:${clientIp(req)}`, RATE_ANON_PER_MIN)) return tooManyRequests(res);
    res.writeHead(200, { "Content-Type": "application/json" });
    // Static registration: every client gets the one pre-configured OIDC client.
    // With a confidential client the secret is handed out here, so it only protects
    // against clients that cannot reach this server — keep the server internal.
    res.end(JSON.stringify({
      client_id: OIDC_CLIENT_ID,
      ...(OIDC_CLIENT_SECRET ? { client_secret: OIDC_CLIENT_SECRET } : {}),
      redirect_uris: ["http://localhost"],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: OIDC_CLIENT_SECRET ? "client_secret_post" : "none"
    }));
    return;
  }

  if (req.url?.startsWith("/mcp")) {
    // Every request must carry the user's access token: Authorization: Bearer <token>
    const authHeader = req.headers["authorization"];
    const hasBearer = !!authHeader && authHeader.startsWith("Bearer ");
    let token = hasBearer ? authHeader.substring(7) : null;
    const sessionId = req.headers["mcp-session-id"];
    let parsedBody;
    if (!token && LEGACY_TOKEN_ARG) {
      // Desktop extensions before 2.1 open their session without a token and send it as a
      // session_token tool argument. Turn LEGACY_TOKEN_ARG off once every user has updated.
      if (req.method === "POST") {
        try { parsedBody = await readJsonBody(req); }
        catch (e) { res.writeHead(400, { "Content-Type": "application/json" }); res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32700, message: "Parse error" }, id: null })); return; }
        const args = parsedBody && !Array.isArray(parsedBody) ? parsedBody.params?.arguments : null;
        if (args && typeof args === "object") {
          if (typeof args.session_token === "string") token = args.session_token;
          delete args.session_token;
        }
      }
      if (!token && sessionId) token = sessionTokenMap.get(sessionId) || null;
    }
    const user = token ? await validateJWT(token) : null;

    if (rateLimited(user ? `user:${user.email}` : `ip:${clientIp(req)}`, user ? RATE_USER_PER_MIN : RATE_ANON_PER_MIN)) return tooManyRequests(res);
    if (!user && (hasBearer || !LEGACY_TOKEN_ARG)) {
      res.writeHead(401, {
        "WWW-Authenticate": `Bearer realm="${MCP_SERVER_URL}", resource_metadata="${MCP_SERVER_URL}/.well-known/oauth-protected-resource"`,
        "Content-Type": "application/json"
      });
      res.end(JSON.stringify({ error: "invalid_token", error_description: "A valid access token is required" }));
      return;
    }

    // Unknown or expired session id (after a restart or idle eviction): answer 404 as the MCP spec
    // requires, so clients start a new session instead of failing with 400 "Server not initialized".
    // A session also belongs to the user who opened it.
    const owner = sessionId ? sessionOwner.get(sessionId) : undefined;
    if (sessionId && (!mcpTransports.has(sessionId) || (user && owner && owner !== user.email))) {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32001, message: "Session not found" }, id: null }));
      return;
    }
    if (sessionId) {
      sessionLastSeen.set(sessionId, Date.now());
      if (user) { sessionTokenMap.set(sessionId, token); sessionOwner.set(sessionId, user.email); }
    }

    let transport = sessionId ? mcpTransports.get(sessionId) : null;
    if (!transport) {
      if (mcpTransports.size >= MAX_SESSIONS) {
        res.writeHead(503, { "Content-Type": "application/json", "Retry-After": "60" });
        res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32000, message: "Server is busy: too many open sessions" }, id: null }));
        return;
      }
      if (user) evictOldestSessions(user.email);
      const sessionRef = { id: null };
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        enableJsonResponse: true,
        onsessioninitialized: (id) => {
          sessionRef.id = id;
          sessionLastSeen.set(id, Date.now());
          mcpTransports.set(id, transport);
          if (user) { sessionTokenMap.set(id, token); sessionOwner.set(id, user.email); }
        }
      });
      transport.onclose = () => { if (transport.sessionId) forgetSession(transport.sessionId); };
      await buildMcpServer(user ? token : null, sessionRef).connect(transport);
    }
    await transport.handleRequest(req, res, parsedBody);
    return;
  }
  res.writeHead(404); res.end("Not found");
});

// Attachment files are deleted 10 minutes after download links are issued; remove any a restart left behind.
try {
  for (const f of readdirSync("/tmp")) if (f.startsWith("exchange-att-")) { try { unlinkSync(`/tmp/${f}`); } catch (e) {} }
} catch (e) {}

httpServer.listen(PORT, "127.0.0.1", () => {
  console.log(`✅ Exchange MCP Server v2.0 running on port ${PORT}`);
});
