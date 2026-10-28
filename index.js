import { writeFileSync, unlinkSync } from 'fs';
import { setTimeout as setTimeoutP } from 'timers';
import * as jose from "jose";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import { createServer } from "http";
import { randomUUID } from "crypto";
import httpntlm from "httpntlm";
import {
  MAIL_DOMAIN, EWS_URL, SVC_USERNAME, SVC_PASSWORD, SVC_UPN,
  OIDC_ISSUER, OIDC_JWKS_URL, OIDC_AUTH_BASE, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET,
  PUBLIC_URL, PORT, LDAP_URLS, LDAP_BASE_DN, LDAPS_CA,
  ROOMS, RESTRICTED_ROOMS, EXCLUDED_ROOMS, ROOM_SIZE_GUIDE
} from "./config.js";

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
  const daysFa = ['\u06cc\u06a9\u0634\u0646\u0628\u0647','\u062f\u0648\u0634\u0646\u0628\u0647','\u0633\u0647\u200c\u0634\u0646\u0628\u0647','\u0686\u0647\u0627\u0631\u0634\u0646\u0628\u0647','\u067e\u0646\u062c\u0634\u0646\u0628\u0647','\u062c\u0645\u0639\u0647','\u0634\u0646\u0628\u0647'];
  const [y, mo, dd] = dateStr.split('-').map(Number);
  const target = Date.UTC(y, mo - 1, dd);
  const dow = new Date(target).getUTCDay();
  const [ty, tmo, tdd] = todayIran().split('-').map(Number);
  const diff = Math.round((target - Date.UTC(ty, tmo - 1, tdd)) / 86400000);
  let rel;
  if (diff === 0) rel = '\u0627\u0645\u0631\u0648\u0632';
  else if (diff === 1) rel = '\u0641\u0631\u062f\u0627';
  else if (diff === -1) rel = '\u062f\u06cc\u0631\u0648\u0632 \u26a0\ufe0f';
  else if (diff > 1) rel = diff + ' \u0631\u0648\u0632 \u062f\u06cc\u06af\u0631';
  else rel = Math.abs(diff) + ' \u0631\u0648\u0632 \u067e\u06cc\u0634 \u26a0\ufe0f';
  return daysFa[dow] + ' ' + dateStr + ' (' + rel + ')';
}

function normalizePersianName(name) {
  if (!name) return '';
  return name
    .replace(/\s+/g, '') // remove all spaces
    .replace(/ي/g, 'ی')  // normalize Arabic ya to Persian ya
    .replace(/ك/g, 'ک')  // normalize Arabic kaf to Persian kaf
    .replace(/ة/g, 'ه')  // normalize ta marbuta
    .replace(/أ|إ|آ/g, 'ا') // normalize alef variants
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
    const { payload } = await jose.jwtVerify(token, _jwks, { issuer: OIDC_ISSUER });
    return payload;
  } catch {
    return null;
  }
}

const SLOT_DURATION_MIN = 60;
const WORK_START_HOUR = 9;
const WORK_END_HOUR = 22;
const WORK_DAYS = [0, 1, 2, 3, 6]; // Sun=0 Mon=1 ... Sat=6 → Sat=6,Sun=0,Mon=1,Tue=2,Wed=3

// ─── Auxiliary HTTP server (OAuth callback, attachment downloads) ─────────────
import "./login-server.js";
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
      c.bind(SVC_UPN, SVC_PASSWORD, (err) => {
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
    const mgr = await ldapSearch(client, LDAP_BASE_DN, `(mail=${managerEmail})`, ['distinguishedName','displayName']);
    if (!mgr.length) return null;
    const managerDN = ldapAttr(mgr[0], 'distinguishedName');
    const managerName = ldapAttr(mgr[0], 'displayName');
    const reports = await ldapSearch(client, LDAP_BASE_DN,
      `(&(objectClass=user)(manager=${managerDN})(mail=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))`,
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
    ? body.replace(/<soap:Body>/, `<soap:Header><t:ExchangeImpersonation><t:ConnectingSID><t:PrimarySmtpAddress>${impersonateEmail}</t:PrimarySmtpAddress></t:ConnectingSID></t:ExchangeImpersonation></soap:Header><soap:Body>`)
    : body;
  return new Promise((resolve, reject) => {
    httpntlm.post({
      url: EWS_URL, username: actualUser, password: actualPass, workstation: "", domain: "",
      body: finalBody,
      headers: { "Content-Type": "text/xml; charset=utf-8", "Accept": "text/xml" },
      rejectUnauthorized: false
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
      <m:UnresolvedEntry>${q}</m:UnresolvedEntry>
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
      <m:RoomList><t:EmailAddress>${listEmail}</t:EmailAddress></m:RoomList>
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
  // e.g. "m5@example.com" -> match "room-m5@example.com"
  const match = keys.find(k => {
    const shortName = k.replace('room-','').split('@')[0]; // e.g. "m5"
    const inputName = lower.split('@')[0]; // e.g. "m5"
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
    `<t:MailboxData><t:Email><t:Address>${e}</t:Address></t:Email><t:AttendeeType>Required</t:AttendeeType></t:MailboxData>`
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
          <t:StartTime>${startDate}</t:StartTime>
          <t:EndTime>${endDate}</t:EndTime>
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
function isWorkDay(date) {
  const day = date.getDay(); // 0=Sun,1=Mon,...,5=Fri,6=Sat
  return day !== 5; // Friday is off
}

function generateSlots(dateStr) {
  const slots = [];
  const [year, month, day] = dateStr.split('-').map(Number);
  const date = new Date(Date.UTC(year, month-1, day));
  if (!isWorkDay(date)) return slots;
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
      if (!avail) { conflicts.push({ date, busy: ['(بررسی ناموفق بود)'] }); continue; }
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
      <m:CalendarView MaxEntriesReturned="1000" StartDate="${startDate}T00:00:00" EndDate="${endDate}T23:59:59"/>
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
    `<t:Attendee><t:Mailbox><t:EmailAddress>${e}</t:EmailAddress></t:Mailbox></t:Attendee>`
  ).join("");

  let recurrenceXml = '';
  if (recurrence && recurrence.type) {
    const { type, interval = 1, endDate, occurrences } = recurrence;
    let patternXml = '';
    if (type === 'daily') {
      patternXml = `<t:DailyRecurrence><t:Interval>${interval}</t:Interval></t:DailyRecurrence>`;
    } else if (type === 'weekly') {
      const days = ['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'];
      const [dp] = start.split('T');
      const [y,mo,dd] = dp.split('-').map(Number);
      const dow = days[new Date(Date.UTC(y, mo-1, dd)).getUTCDay()];
      patternXml = `<t:WeeklyRecurrence><t:Interval>${interval}</t:Interval><t:DaysOfWeek>${dow}</t:DaysOfWeek></t:WeeklyRecurrence>`;
    } else if (type === 'monthly') {
      const dayOfMonth = parseInt(start.split('T')[0].split('-')[2]);
      patternXml = `<t:AbsoluteMonthlyRecurrence><t:Interval>${interval}</t:Interval><t:DayOfMonth>${dayOfMonth}</t:DayOfMonth></t:AbsoluteMonthlyRecurrence>`;
    }
    const startDate = start.split('T')[0];
    let rangeXml = endDate
      ? `<t:EndDateRecurrence><t:StartDate>${startDate}</t:StartDate><t:EndDate>${endDate}</t:EndDate></t:EndDateRecurrence>`
      : `<t:NumberedRecurrence><t:StartDate>${startDate}</t:StartDate><t:NumberOfOccurrences>${occurrences || 10}</t:NumberOfOccurrences></t:NumberedRecurrence>`;
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
          <t:Start>${start}</t:Start>
          <t:End>${end}</t:End>
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
      <m:ItemIds>${itemIds.map(id => `<t:ItemId Id="${id}"/>`).join("")}</m:ItemIds>
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
      <m:ItemIds><t:ItemId Id="${itemId}"/></m:ItemIds>
    </m:DeleteItem>
  </soap:Body>
</soap:Envelope>`;
  const resp = await ewsRequest(SVC_USERNAME, SVC_PASSWORD, xml, mailbox);
  if (/ResponseClass="Error"/.test(resp)) {
    throw new Error((resp.match(/<(?:[^:>]+:)?MessageText>([^<]+)</) || [])[1] || "delete failed");
  }
}

function xmlEscape(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
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
  const ids = itemIds.map(id => `<t:ItemId Id="${id}"/>`).join("");
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
      <m:CalendarView MaxEntriesReturned="100" StartDate="${start}" EndDate="${end}"/>
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
      <m:ItemIds><t:ItemId Id="${itemId}"/></m:ItemIds>
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
      <m:ItemIds><t:RecurringMasterItemId OccurrenceId="${itemId}"/></m:ItemIds>
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
      <m:ItemIds><t:ItemId Id="${itemId}" ChangeKey="${changeKey}"/></m:ItemIds>
    </m:DeleteItem>
  </soap:Body>
</soap:Envelope>`;
    await ewsRequest(SVC_USERNAME, SVC_PASSWORD, xml, userEmail);
    return;
  }
  if (affectedOccurrences === 'AllFollowingOccurrences') {
    const xml = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Body>
    <m:DeleteItem DeleteType="MoveToDeletedItems" SendMeetingCancellations="SendToAllAndSaveCopy">
      <m:ItemIds><t:ItemId Id="${itemId}" ChangeKey="${changeKey}"/></m:ItemIds>
    </m:DeleteItem>
  </soap:Body>
</soap:Envelope>`;
    await ewsRequest(SVC_USERNAME, SVC_PASSWORD, xml, userEmail);
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
      <m:ItemIds><t:ItemId Id="${deleteId}" ChangeKey="${deleteCK || changeKey}"/></m:ItemIds>
    </m:DeleteItem>
  </soap:Body>
</soap:Envelope>`;
  await ewsRequest(SVC_USERNAME, SVC_PASSWORD, xml, userEmail);
}

async function updateEvent(userEmail, { itemId, changeKey, subject, start, end, location, roomEmail, body, attendeeEmails, affectedOccurrences = 'AllOccurrences' }) {
  const fields = [];
  if (subject) fields.push(`<t:SetItemField><t:FieldURI FieldURI="item:Subject"/><t:CalendarItem><t:Subject>${subject}</t:Subject></t:CalendarItem></t:SetItemField>`);
  if (start) fields.push(`<t:SetItemField><t:FieldURI FieldURI="calendar:Start"/><t:CalendarItem><t:Start>${start}</t:Start></t:CalendarItem></t:SetItemField>`);
  if (end) fields.push(`<t:SetItemField><t:FieldURI FieldURI="calendar:End"/><t:CalendarItem><t:End>${end}</t:End></t:CalendarItem></t:SetItemField>`);
  if (location !== undefined) {
    fields.push(`<t:DeleteItemField><t:FieldURI FieldURI="calendar:Location"/></t:DeleteItemField>`);
    if (location) fields.push(`<t:SetItemField><t:FieldURI FieldURI="calendar:Location"/><t:CalendarItem><t:Location>${getRoomDisplayName(location)}</t:Location></t:CalendarItem></t:SetItemField>`);
  }
  if (body) fields.push(`<t:SetItemField><t:FieldURI FieldURI="item:Body"/><t:CalendarItem><t:Body BodyType="Text">${body}</t:Body></t:CalendarItem></t:SetItemField>`);
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
        `<t:Attendee><t:Mailbox><t:EmailAddress>${e}</t:EmailAddress></t:Mailbox></t:Attendee>`
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
    <m:UpdateItem MessageDisposition="SaveOnly" ConflictResolution="AlwaysOverwrite"
                  SendMeetingInvitationsOrCancellations="SendToAllAndSaveCopy">
      <m:ItemChanges>
        <t:ItemChange>
          <t:ItemId Id="${useItemId}" ChangeKey="${useChangeKey}"/>
          <t:Updates>${fields.join("")}</t:Updates>
        </t:ItemChange>
      </m:ItemChanges>
    </m:UpdateItem>
  </soap:Body>
</soap:Envelope>`;
  const resp = await ewsRequest(SVC_USERNAME, SVC_PASSWORD, xml, userEmail);

}


// ─── EWS: List Emails ────────────────────────────────────────────────────────
async function listEmails(userEmail, opts) {
  const { unreadOnly = false, from: fromFilter = null, startDate = null, endDate = null, maxCount = 20 } = opts || {};
  const restrictions = [];
  if (unreadOnly) restrictions.push('<t:IsEqualTo><t:FieldURI FieldURI="message:IsRead"/><t:FieldURIOrConstant><t:Constant Value="false"/></t:FieldURIOrConstant></t:IsEqualTo>');
  if (fromFilter) restrictions.push(`<t:Contains ContainmentMode="Substring" ContainmentComparison="IgnoreCase"><t:FieldURI FieldURI="message:From"/><t:Constant Value="${fromFilter}"/></t:Contains>`);
  if (startDate) restrictions.push(`<t:IsGreaterThanOrEqualTo><t:FieldURI FieldURI="item:DateTimeReceived"/><t:FieldURIOrConstant><t:Constant Value="${startDate}"/></t:FieldURIOrConstant></t:IsGreaterThanOrEqualTo>`);
  if (endDate) restrictions.push(`<t:IsLessThanOrEqualTo><t:FieldURI FieldURI="item:DateTimeReceived"/><t:FieldURIOrConstant><t:Constant Value="${endDate}"/></t:FieldURIOrConstant></t:IsLessThanOrEqualTo>`);
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
      <m:IndexedPageItemView MaxEntriesReturned="${maxCount}" Offset="0" BasePoint="Beginning"/>
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
      <m:ItemIds><t:ItemId Id="${itemId}"/></m:ItemIds>
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
  const body = bodyMatch ? bodyMatch[1].replace(/<[^>]+>/g, "").trim() : "";
  try { await markEmailAsRead(username, password, itemId); } catch {}
  return { subject, body, fromName, fromEmail, received };
}

async function markEmailAsRead(userEmail, itemId) {
  const xml = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Body>
    <m:UpdateItem MessageDisposition="SaveOnly" ConflictResolution="AlwaysOverwrite">
      <m:ItemChanges><t:ItemChange><t:ItemId Id="${itemId}"/>
        <t:Updates><t:SetItemField><t:FieldURI FieldURI="message:IsRead"/><t:Message><t:IsRead>true</t:IsRead></t:Message></t:SetItemField></t:Updates>
      </t:ItemChange></m:ItemChanges>
    </m:UpdateItem>
  </soap:Body>
</soap:Envelope>`;
  const resp = await ewsRequest(SVC_USERNAME, SVC_PASSWORD, xml, userEmail);

}


async function getAttachments(userEmail, itemId) {
  const xml1 = `<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"><soap:Body><m:GetItem><m:ItemShape><t:BaseShape>IdOnly</t:BaseShape><t:AdditionalProperties><t:FieldURI FieldURI="item:Attachments"/></t:AdditionalProperties></m:ItemShape><m:ItemIds><t:ItemId Id="${itemId}"/></m:ItemIds></m:GetItem></soap:Body></soap:Envelope>`;
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
  const toXml = to.map(e => `<t:Mailbox><t:EmailAddress>${e}</t:EmailAddress></t:Mailbox>`).join("");
  const ccXml = cc.map(e => `<t:Mailbox><t:EmailAddress>${e}</t:EmailAddress></t:Mailbox>`).join("");
  const bccXml = bcc.map(e => `<t:Mailbox><t:EmailAddress>${e}</t:EmailAddress></t:Mailbox>`).join("");
  const xml = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Body>
    <m:CreateItem MessageDisposition="SendAndSaveCopy">
      <m:SavedItemFolderId><t:DistinguishedFolderId Id="sentitems"/></m:SavedItemFolderId>
      <m:Items>
        <t:Message>
          <t:Subject>${subject}</t:Subject>
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
          <t:ReferenceItemId Id="${itemId}"/>
        </t:${tag}>
      </m:Items>
    </m:CreateItem>
  </soap:Body>
</soap:Envelope>`;
  const resp = await ewsRequest(SVC_USERNAME, SVC_PASSWORD, xml, userEmail);

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
      `(mail=${groupEmail})`, ['distinguishedName']);
    if (!groupEntries.length) {
      // Try by sAMAccountName (group alias without domain)
      const alias = groupEmail.split('@')[0];
      const aliasEntries = await ldapSearch(client, LDAP_BASE_DN,
        `(|(sAMAccountName=${alias})(cn=${alias}))`, ['distinguishedName']);
      if (!aliasEntries.length) { try { client.unbind(); } catch(e) {} return false; }
      const groupDN = ldapAttr(aliasEntries[0], 'distinguishedName');
      // Check if user is member (recursive via LDAP_MATCHING_RULE_IN_CHAIN)
      const userEntries = await ldapSearch(client, LDAP_BASE_DN,
        `(&(mail=${userEmail})(memberOf:1.2.840.113556.1.4.1941:=${groupDN}))`,
        ['mail']);
      try { client.unbind(); } catch(e) {}
      return userEntries.length > 0;
    }
    const groupDN = ldapAttr(groupEntries[0], 'distinguishedName');
    // LDAP_MATCHING_RULE_IN_CHAIN (1.2.840.113556.1.4.1941) checks nested membership
    const userEntries = await ldapSearch(client, LDAP_BASE_DN,
      `(&(mail=${userEmail})(memberOf:1.2.840.113556.1.4.1941:=${groupDN}))`,
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
      <m:Mailbox><t:EmailAddress>${groupEmail}</t:EmailAddress></m:Mailbox>
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
    return { allowed: false, reason: "این اتاق در دسترس نیست." };
  }
  const groupEmail = RESTRICTED_ROOMS[roomEmail];
  if (!groupEmail) return { allowed: true };
  const isMember = await checkUserInGroup(groupEmail, new Set(), userEmail);
  if (isMember) return { allowed: true };
  const roomName = roomEmail.split("@")[0].replace("room-","").toUpperCase();
  return { allowed: false, reason: "متاسفانه شما به اتاق " + roomName + " دسترسی ندارید. برای دسترسی با IT تماس بگیرید." };
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
          altText = `\n\nاتاق‌های در دسترس شما که در این بازه آزادند:\n` +
            freeRooms.map(e => `  • ${getRoomDisplayName(e)} — ${e}`).join('\n');
        }
      }
    }
  } catch {}
  return `❌ ${reason}${altText}\n\n(این اتاق نباید در پیش‌نمایش رزرو نشان داده می‌شد — پیش از رزرو دسترسی را با list_rooms بررسی کن.)`;
}


// ─── MCP Server ───────────────────────────────────────────────────────────────
// Global session token map — allows updating autoToken after session creation
const sessionTokenMap = new Map();

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
    if (now - seen < SESSION_IDLE_MS) continue;
    sessionLastSeen.delete(id);
    const tr = mcpTransports.get(id);
    mcpTransports.delete(id); mcpTransports.delete(id + '_token'); sessionTokenMap.delete(id);
    if (tr) { try { tr.close(); } catch (e) {} }
  }
}, SESSION_SWEEP_MS).unref();

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
Never output any URL. Never ask user to log in or send a token. Authentication is 100% automatic — just call any tool and the DXT opens Keycloak browser automatically. After logout respond ONLY with "✅ خارج شدی." — nothing else.

## TIME GATE -- MANDATORY, NO EXCEPTIONS
*** You do NOT know today's date. NEVER assume, guess, or rely on any date from the conversation history, your training, or the system context. The ONLY valid source of the current date is the get_current_time tool. ***
- The MOMENT the user uses ANY relative time reference (today, tomorrow, yesterday, tonight, now, this week, next week, this month, day-after-tomorrow, or any weekday name, or their Persian equivalents), you MUST call get_current_time FIRST, before any other tool (list_events, smart_schedule, check_availability, etc.).
- Do this even if you think you already know the date, and even if a date already appeared earlier in this conversation -- dates in history may be stale or wrong. Re-fetch every time you resolve a relative reference.
- All times are Iran timezone (UTC+3:30). Never convert to UTC.
- To compute "this week": call get_current_time, read the Day field, then derive the Saturday-to-Friday range from that exact date. Never derive a week range from a remembered date.

## ROOM ACCESS GATE — MANDATORY, NO EXCEPTIONS
*** Whenever a specific room is named or chosen, you MUST call list_rooms BEFORE showing any preview or calling smart_schedule. ***
- This applies even when the user names the room directly ("تو اتاق S5", "اتاق N2"). Naming a room is NOT permission — you still must verify access first.
- Read the ✅/🔒 status for that exact room from list_rooms output.
- If 🔒: STOP. Do not preview it, do not call smart_schedule, do not "try anyway". Tell the user they don't have access and offer ✅ same-size alternatives.
- If ✅: proceed to preview, then book.
- NEVER rely on smart_schedule's server-side error to discover access — that wastes a confirmation and shows the user a preview for a room they can't book. Catch it earlier with list_rooms.

## BOOKING FLOW — ALWAYS follow this order
1. Collect: subject, date/time, attendees, duration (default 60 min)
2. Ask about room if not mentioned: "می‌خوای اتاق هم رزرو کنم؟"
3. The MOMENT any room is named or chosen → call list_rooms and read its ✅/🔒 status (see ROOM ACCESS GATE above). A 🔒 room never reaches the preview. If the named room is 🔒, tell the user they lack access and offer ✅ alternatives — do NOT preview or offer to "try anyway".
4. Show preview: subject, date/time, attendees, room (room MUST be ✅ — already verified in step 3) — ask confirmation
5. WAIT for explicit user confirmation — "بله", "آره", "ok", "yes", "تایید" — NEVER book without this
6. *** IMMEDIATELY BEFORE BOOKING: call check_availability again for ALL attendees + chosen room ***
7. Only after confirmation AND fresh availability check: execute booking
*** CRITICAL: Never auto-book. Never skip confirmation. Even if user says "همون" or "نک" — still show preview and wait for explicit yes ***

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
- "تیم X" or "زیرمجموعه X" means manager + all direct reports

## RECURRING EVENTS — CRITICAL
*** NEVER create separate meetings for recurring requests. ALWAYS use recurrence param in smart_schedule ***
- Weekly 4 weeks: recurrence={type:'weekly',interval:1,occurrences:4}
- Weekly 1 month: recurrence={type:'weekly',interval:1,occurrences:4}
- Daily 5 days: recurrence={type:'daily',interval:1,occurrences:5}
- Monthly 3 months: recurrence={type:'monthly',interval:1,occurrences:3}
- With end date: recurrence={type:'weekly',interval:1,end_date:'2026-08-01'}
If user says "هر هفته", "هفتگی", "هر روز", "ماهانه", "تکرارشونده", "recurring" → MUST use recurrence param
NEVER say "ابزار recurring ندارم" — smart_schedule HAS recurrence param, always use it
- For delete: ask "فقط این جلسه، این و بعدی‌ها، یا کل سری؟" → SpecifiedOccurrenceOnly | AllFollowingOccurrences | AllOccurrences

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
- "امشب", "امروز", "فردا" all mean the FULL day from 00:00:00 to 23:59:59
- If first call returns empty, retry with same range before giving up

## AVAILABILITY — CRITICAL RULE
- *** ALWAYS do a final fresh check_availability call immediately before every book or update execution ***
- *** Never rely on availability data from earlier in the conversation — even 10 seconds old data is stale ***
- Always include room email in availability check`,
  });



  // ── search_user ──
  server.tool("search_user",
    "Search for a user by name (Persian or English) to get their email address.",
    { session_token: z.string().optional().optional(), query: z.string().describe("Name to search, e.g. علی محمدی or ali") },
    async ({ session_token, query }) => {
      // Ignore session_token if it looks like a placeholder (not a real JWT or UUID)
    const isRealToken = (t) => t && (t.startsWith("eyJ") || /^[0-9a-f-]{36}$/.test(t));
    const _resolvedToken = (isRealToken(session_token) ? session_token : null) || getAutoToken();
    const payload = await validateJWT(_resolvedToken);
      if (!payload) return { content: [{ type: "text", text: "❌ Session expired. Please try again — a browser will open to log in automatically." }] };
      const userEmail = payload.email;
      const userName = payload.preferred_username;
      try {
        const results = await resolveNames(query);
        if (!results.length) return { content: [{ type: "text", text: `هیچ کاربری با نام "${query}" پیدا نشد. نام را با فرمت دیگری امتحان کنید.` }] };

        // Auto-select if only 1 result or top result is clearly best (score >= 80 and much higher than #2)
        const top = results[0];
        const second = results[1];
        const clearWinner = top.score >= 80 && (!second || top.score - second.score >= 20);

        if (results.length === 1 || clearWinner) {
          return { content: [{ type: "text", text: `✅ یافت شد: ${top.name} <${top.email}>\n💡 برای یافتن زیرمجموعه‌ها، get_direct_reports را با manager_email: ${top.email} فراخوانی کنید.` }] };
        }

        // Show top 10 only
        const topResults = results.slice(0, 10);
        const list = topResults.map((r, i) => `${i+1}. ${r.name} <${r.email}>`).join("\n");
        const moreMsg = results.length > 10
          ? `\n\n⚠️ ${results.length} نفر یافت شد — فقط ۱۰ نفر اول نشان داده شد. نام دقیق‌تری وارد کنید.`
          : '';
        return { content: [{ type: "text", text: `${topResults.length} کاربر یافت شد:\n${list}${moreMsg}\n\nکدام یکی؟` }] };
      } catch (e) { return { content: [{ type: "text", text: `❌ ${e.message}` }] }; }
    }
  );

  // ── resolve_group ──




  server.tool("get_direct_reports",
    "Find all direct reports (subordinates) of a manager using Exchange directory. ALWAYS call this after search_user finds a manager, when user wants to meet or email their team. Triggers: 'people under X', 'X team', 'زیرمجموعه X', 'کسانی که مدیرشون X هست', 'تیم X'.",
    {
      session_token:  z.string(),
      manager_email:  z.string().describe("Email of the manager")
    },
    async ({ session_token, manager_email }) => {
      const isRealToken = (t) => t && (t.startsWith("eyJ") || /^[0-9a-f-]{36}$/.test(t));
    const _resolvedToken = (isRealToken(session_token) ? session_token : null) || getAutoToken();
    const payload = await validateJWT(_resolvedToken);
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
    "Find the manager of a user using LDAP directory. Use when user asks 'who is my manager', 'مدیرم کیه', 'مدیر X کیه', 'boss of X'.",
    {
      session_token: z.string().optional().optional(),
      user_email: z.string().describe("Email of the user to find the manager for")
    },
    async ({ session_token, user_email }) => {
      const isRealToken = (t) => t && (t.startsWith("eyJ") || /^[0-9a-f-]{36}$/.test(t));
    const _resolvedToken = (isRealToken(session_token) ? session_token : null) || getAutoToken();
    const payload = await validateJWT(_resolvedToken);
      if (!payload) return { content: [{ type: "text", text: "❌ Session expired. Please try again — a browser will open to log in automatically." }] };
      try {
        const client = await getLdapClient();
        if (!client) return { content: [{ type: "text", text: "❌ LDAP unreachable" }] };
        const entries = await ldapSearch(client, LDAP_BASE_DN,
          `(mail=${user_email})`,
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
          `(distinguishedName=${managerDN})`,
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
    { session_token: z.string().optional().optional(), query: z.string().describe("Group name or email e.g. backend-team@example.com") },
    async ({ session_token, query }) => {
      const isRealToken = (t) => t && (t.startsWith("eyJ") || /^[0-9a-f-]{36}$/.test(t));
    const _resolvedToken = (isRealToken(session_token) ? session_token : null) || getAutoToken();
    const payload = await validateJWT(_resolvedToken);
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
    { session_token: z.string().optional().optional(), user_email: z.string().describe("Email of the person to find teammates for") },
    async ({ session_token, user_email }) => {
      const isRealToken = (t) => t && (t.startsWith("eyJ") || /^[0-9a-f-]{36}$/.test(t));
    const _resolvedToken = (isRealToken(session_token) ? session_token : null) || getAutoToken();
    const payload = await validateJWT(_resolvedToken);
      if (!payload) return { content: [{ type: "text", text: "❌ Session expired. Please try again — a browser will open to log in automatically." }] };
      try {
        const client = await getLdapClient();
        if (!client) return { content: [{ type: "text", text: "❌ LDAP unreachable" }] };
        const entries = await ldapSearch(client, LDAP_BASE_DN, `(mail=${user_email})`, ['displayName','manager']);
        try { client.unbind(); } catch(e) {}
        if (!entries.length) return { content: [{ type: "text", text: `❌ User ${user_email} not found` }] };
        const managerDN = ldapAttr(entries[0], 'manager');
        const userName  = ldapAttr(entries[0], 'displayName');
        if (!managerDN) return { content: [{ type: "text", text: `⚠️ No manager found for ${userName}` }] };
        const client2 = await getLdapClient();
        if (!client2) return { content: [{ type: "text", text: "❌ LDAP unreachable" }] };
        const mgr = await ldapSearch(client2, LDAP_BASE_DN, `(distinguishedName=${managerDN})`, ['displayName','mail']);
        const teammates = await ldapSearch(client2, LDAP_BASE_DN, `(&(objectClass=user)(manager=${managerDN})(mail=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))`, ['displayName','mail']);
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
      session_token: z.string().optional().optional(), user_email: z.string(), subject: z.string(),
      date: z.string().describe("YYYY-MM-DD"), start_time: z.string().describe("HH:MM Iran time"),
      duration_minutes: z.number(), room_email: z.string().optional(), confirmed: z.boolean()
    },
    async ({ session_token, user_email, subject, date, start_time, duration_minutes, room_email, confirmed }) => {
      const isRealToken = (t) => t && (t.startsWith("eyJ") || /^[0-9a-f-]{36}$/.test(t));
    const _resolvedToken = (isRealToken(session_token) ? session_token : null) || getAutoToken();
    const payload = await validateJWT(_resolvedToken);
      if (!payload) return { content: [{ type: "text", text: "❌ Session expired. Please try again — a browser will open to log in automatically." }] };
      try {
        const client = await getLdapClient();
        if (!client) return { content: [{ type: "text", text: "❌ LDAP unreachable" }] };
        const entries = await ldapSearch(client, LDAP_BASE_DN, `(mail=${user_email})`, ['manager']);
        try { client.unbind(); } catch(e) {}
        if (!entries.length) return { content: [{ type: "text", text: `❌ User ${user_email} not found` }] };
        const managerDN = ldapAttr(entries[0], 'manager');
        if (!managerDN) return { content: [{ type: "text", text: `⚠️ No manager found for ${user_email}` }] };
        const client2 = await getLdapClient();
        const mgr = await ldapSearch(client2, LDAP_BASE_DN, `(distinguishedName=${managerDN})`, ['mail']);
        const teammates = await ldapSearch(client2, LDAP_BASE_DN, `(&(objectClass=user)(manager=${managerDN})(mail=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))`, ['displayName','mail']);
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
      session_token:    z.string(),
      manager_email:    z.string().describe("Email of the manager"),
      subject:          z.string(),
      date:             z.string().describe("YYYY-MM-DD"),
      start_time:       z.string().describe("HH:MM Iran time"),
      duration_minutes: z.number(),
      room_email:       z.string().optional(),
      confirmed:        z.boolean().describe("false=preview only, true=book")
    },
    async ({ session_token, manager_email, subject, date, start_time, duration_minutes, room_email, confirmed }) => {
      const isRealToken = (t) => t && (t.startsWith("eyJ") || /^[0-9a-f-]{36}$/.test(t));
    const _resolvedToken = (isRealToken(session_token) ? session_token : null) || getAutoToken();
    const payload = await validateJWT(_resolvedToken);
      if (!payload) return { content: [{ type: "text", text: "❌ Session expired. Please try again — a browser will open to log in automatically." }] };
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
      session_token: z.string().optional().optional(),
      manager_email: z.string().describe("Email of the manager"),
      subject:       z.string(),
      body:          z.string(),
      confirmed:     z.boolean().describe("false=preview, true=send")
    },
    async ({ session_token, manager_email, subject, body, confirmed }) => {
      const isRealToken = (t) => t && (t.startsWith("eyJ") || /^[0-9a-f-]{36}$/.test(t));
    const _resolvedToken = (isRealToken(session_token) ? session_token : null) || getAutoToken();
    const payload = await validateJWT(_resolvedToken);
      if (!payload) return { content: [{ type: "text", text: "❌ Session expired. Please try again — a browser will open to log in automatically." }] };
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
    { session_token: z.string().optional().optional(), filter: z.string().optional().describe("Optional filter e.g. 'M' or 'N' or 'S'") },
    async ({ session_token, filter }) => {
      const isRealToken = (t) => t && (t.startsWith("eyJ") || /^[0-9a-f-]{36}$/.test(t));
    const _resolvedToken = (isRealToken(session_token) ? session_token : null) || getAutoToken();
    const payload = await validateJWT(_resolvedToken);
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
          const note = accessible ? " (دسترسی دارید — قابل رزرو)" : " (دسترسی ندارید — با IT تماس بگیرید)";
          return `${i+1}. ${icon} ${r.name}${note}\n   📧 ${r.email}`;
        }).join("\n");
        return { content: [{ type: "text", text: `🏢 ${rooms.length} اتاق (وضعیت دسترسی شما بر اساس عضویت گروه AD):\n\n${list}\n\n⚠️ ✅ یعنی قطعاً دسترسی رزرو دارید — نیازی به تست رزرو نیست. 🔒 یعنی قطعاً دسترسی ندارید.` }] };
      } catch (e) { return { content: [{ type: "text", text: `❌ ${e.message}` }] }; }
    }
  );

  // ── check_availability ──
  server.tool("check_availability",
    "Check free/busy status for users AND rooms on a specific date. Returns every room with its per-user access status from LDAP: ✅ (free + user can book), 🔒 (user has NO access — never suggest), 🔴 (busy). USE THIS when the user asks to find an available room — it is the ONLY source of truth for which rooms this user may book. Never decide room access by name or type; only ✅ rooms are bookable by this user. Do NOT call this before smart_schedule for an already-chosen room (smart_schedule does its own fresh check).",
    {
      session_token: z.string().optional().optional(),
      emails: z.array(z.string()).describe("List of email addresses to check"),
      date: z.string().describe("Date to check e.g. 2026-04-20")
    },
    async ({ session_token, emails, date, start_time, end_time }) => {
      const isRealToken = (t) => t && (t.startsWith("eyJ") || /^[0-9a-f-]{36}$/.test(t));
    const _resolvedToken = (isRealToken(session_token) ? session_token : null) || getAutoToken();
    const payload = await validateJWT(_resolvedToken);
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
          if (!busy.length) { out += `   ✅ آزاد\n`; }
          else { busy.forEach(b => { out += `   🔴 Busy: ${formatDateTime(b.start)} → ${formatDateTime(b.end)}\n`; }); }
          out += "\n";
        }

        out += `🏢 اتاق‌ها (وضعیت دسترسی این کاربر بر اساس LDAP):\n`;
        for (const email of roomEmails) {
          const busy = avail[email] || [];
          const roomName = getRoomDisplayName(email);
          const hasAccess = accessMap[email];
          if (!hasAccess) {
            // Free or busy is irrelevant — user cannot book this room. Do NOT suggest.
            out += `   🔒 ${roomName} — دسترسی ندارید (پیشنهاد نده)\n`;
          } else if (!busy.length) {
            out += `   ✅ ${roomName} — آزاد و قابل رزرو\n`;
          } else {
            out += `   🔴 ${roomName} — مشغول\n`;
          }
        }
        if (freeSlots.length) {
          out += `\n✅ اسلات‌های مشترک آزاد:\n`;
          freeSlots.forEach(sl => { out += `   • ${formatSlot(sl)}\n`; });
        } else {
          out += `\n❌ هیچ اسلات مشترک آزادی در ${date} پیدا نشد.`;
        }
        out += `\n\n⚠️ فقط اتاق‌های ✅ را پیشنهاد بده. اتاق‌های 🔒 را هرگز پیشنهاد نده و درباره دسترسی هیچ اتاقی فرض نکن — این لیست تنها منبع حقیقت است.`;
        return { content: [{ type: "text", text: out }] };
      } catch (e) { return { content: [{ type: "text", text: `❌ ${e.message}` }] }; }
    }
  );

  // ── smart_schedule ──
  server.tool("smart_schedule",
    "Check availability and book a meeting — single OR recurring. Returns a PREVIEW first (nothing is booked); after the user approves, call again with confirmed=true to actually book. Use the recurrence param for weekly/daily/monthly series — it handles the whole series in one call, NEVER create separate meetings. ALWAYS call list_rooms first to get the correct room_email. Suggests alternative slots if the requested time is busy.",
    {
      session_token: z.string().optional(),
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
    async ({ session_token, subject, date, start_time, duration_minutes, attendee_emails: _ae, emails, room_email, body, recurrence, confirmed }) => {
      const attendee_emails = _ae || emails || [];
      const isRealToken = (t) => t && (t.startsWith("eyJ") || /^[0-9a-f-]{36}$/.test(t));
      const _resolvedToken = (isRealToken(session_token) ? session_token : null) || getAutoToken();
      const payload = await validateJWT(_resolvedToken);
      if (!payload) return { content: [{ type: "text", text: "\u274c Session expired. Please try again \u2014 a browser will open to log in automatically." }] };
      const userEmail = payload.email;
      const pad = n => String(n).padStart(2, "0");
      try {
        // Normalize inputs: accept H:MM, HH:MM, HH:MM:SS; reject malformed values up front
        const _tm = String(start_time || "").trim().match(/^(\d{1,2}):(\d{2})(?::\d{2})?$/);
        if (!_tm || Number(_tm[1]) > 23 || Number(_tm[2]) > 59) {
          return { content: [{ type: "text", text: `❌ فرمت ساعت نامعتبر: "${start_time}" — ساعت را به شکل HH:MM بفرست (مثلاً 09:30).` }] };
        }
        start_time = `${pad(Number(_tm[1]))}:${_tm[2]}`;
        date = String(date || "").trim();
        if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
          return { content: [{ type: "text", text: `❌ فرمت تاریخ نامعتبر: "${date}" — تاریخ را به شکل YYYY-MM-DD بفرست.` }] };
        }
        if (!(Number(duration_minutes) > 0)) {
          return { content: [{ type: "text", text: `❌ مدت جلسه باید بیشتر از صفر دقیقه باشد.` }] };
        }
        duration_minutes = Number(duration_minutes);
        if (Number(_tm[1]) * 60 + Number(_tm[2]) + duration_minutes > 24 * 60) {
          return { content: [{ type: "text", text: `❌ جلسه نمی‌تواند از نیمه‌شب عبور کند — ساعت شروع یا مدت را کم کن.` }] };
        }
        // Guard: reject past datetimes
        if (isPastDateTime(`${date}T${start_time}:00`)) {
          return { content: [{ type: "text", text: `\u274c \u0632\u0645\u0627\u0646 \u0627\u0646\u062a\u062e\u0627\u0628\u06cc (${date} ${start_time}) \u06af\u0630\u0634\u062a\u0647 \u0627\u0633\u062a. \u0627\u0645\u0631\u0648\u0632 ${todayIran()} \u0627\u0633\u062a. \u0644\u0637\u0641\u0627\u064b \u0632\u0645\u0627\u0646 \u0622\u06cc\u0646\u062f\u0647\u200c\u0627\u06cc \u0627\u0646\u062a\u062e\u0627\u0628 \u06a9\u0646\u06cc\u062f.` }] };
        }
        // Guard: validate and check room access
        if (room_email) {
          const validRoom = validateRoomEmail(room_email);
          if (validRoom === null) {
            const roomList = Object.entries(ROOM_NAMES).map(([e,n]) => `  \u2022 ${n} \u2014 ${e}`).join('\n');
            return { content: [{ type: "text", text: `\u274c \u0627\u06cc\u0645\u06cc\u0644 \u0627\u062a\u0627\u0642 \u0646\u0627\u0645\u0639\u062a\u0628\u0631: "${room_email}"\n\n\u0627\u062a\u0627\u0642\u200c\u0647\u0627\u06cc \u0645\u0648\u062c\u0648\u062f:\n${roomList}` }] };
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
          let p = `\u{1F4CB} \u067e\u06cc\u0634\u200c\u0646\u0645\u0627\u06cc\u0634 \u2014 \u0647\u0646\u0648\u0632 \u0686\u06cc\u0632\u06cc \u062b\u0628\u062a \u0646\u0634\u062f\u0647 \u0648 \u062f\u0639\u0648\u062a\u200c\u0646\u0627\u0645\u0647\u200c\u0627\u06cc \u0627\u0631\u0633\u0627\u0644 \u0646\u0634\u062f\u0647.\n\n`;
          p += `\u{1F4CC} \u0645\u0648\u0636\u0648\u0639: ${subject}\n`;
          p += `\u{1F4C5} \u062a\u0627\u0631\u06cc\u062e: ${describeDate(date)}\n`;
          p += `\u{1F552} \u0633\u0627\u0639\u062a: ${start_time} \u062a\u0627 ${_pe}\n`;
          p += `\u{1F4CD} \u0627\u062a\u0627\u0642: ${room_email ? getRoomDisplayName(room_email) : "\u0628\u062f\u0648\u0646 \u0627\u062a\u0627\u0642"}\n`;
          p += `\u{1F465} \u0634\u0631\u06a9\u062a\u200c\u06a9\u0646\u0646\u062f\u06af\u0627\u0646: ${attendee_emails && attendee_emails.length ? attendee_emails.join("\u060c ") : "\u0628\u062f\u0648\u0646 \u0634\u0631\u06a9\u062a\u200c\u06a9\u0646\u0646\u062f\u0647"}\n`;
          if (occDates && occDates.length > 1) {
            p += `\u{1F501} \u062a\u06a9\u0631\u0627\u0631: ${recurrence.type} \u2014 ${occDates.length} \u062c\u0644\u0633\u0647\n`;
            occDates.slice(0, 10).forEach(d => { p += `   \u2022 ${describeDate(d)}\n`; });
            if (occDates.length > 10) p += `   \u2026 \u0648 ${occDates.length - 10} \u0645\u0648\u0631\u062f \u062f\u06cc\u06af\u0631\n`;
          }
          p += `\n\u2705 \u0647\u0645\u0647 \u062f\u0631 \u0627\u06cc\u0646 \u0632\u0645\u0627\u0646 \u0622\u0632\u0627\u062f \u0647\u0633\u062a\u0646\u062f.\n`;
          p += `\n\u26a0\ufe0f \u0627\u06cc\u0646 \u067e\u06cc\u0634\u200c\u0646\u0645\u0627\u06cc\u0634 \u0631\u0627 \u0639\u06cc\u0646\u0627\u064b \u0628\u0647 \u06a9\u0627\u0631\u0628\u0631 \u0646\u0634\u0627\u0646 \u0628\u062f\u0647 \u0648 \u0645\u0646\u062a\u0638\u0631 \u062a\u0623\u06cc\u06cc\u062f \u0635\u0631\u06cc\u062d \u0628\u0645\u0627\u0646. \u0628\u0639\u062f \u0627\u0632 \u062a\u0623\u06cc\u06cc\u062f\u060c \u0647\u0645\u06cc\u0646 \u0627\u0628\u0632\u0627\u0631 \u0631\u0627 \u0628\u0627 confirmed=true \u0635\u062f\u0627 \u0628\u0632\u0646.`;
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
            let msg = `\u274c \u062c\u0644\u0633\u0647 \u062b\u0628\u062a \u0646\u0634\u062f. \u0627\u062a\u0627\u0642 ${roomName} \u062f\u0631 ${verify.missing.length} \u0645\u0648\u0631\u062f \u0627\u0632 ${occDates.length} \u062a\u0627\u0631\u06cc\u062e\u0650 \u0633\u0631\u06cc \u062f\u0631 \u0633\u0627\u0639\u062a ${hhmm} \u0642\u0628\u0648\u0644 \u0646\u06a9\u0631\u062f (\u062a\u062f\u0627\u062e\u0644 \u06cc\u0627 \u0639\u062f\u0645 \u062f\u0633\u062a\u0631\u0633\u06cc):\n`;
            verify.missing.slice(0, 15).forEach(d => { msg += `  \ud83d\udd34 ${d}\n`; });
            if (verify.missing.length > 15) msg += `  \u2026 \u0648 ${verify.missing.length - 15} \u0645\u0648\u0631\u062f \u062f\u06cc\u06af\u0631\n`;
            msg += rb.rolledBack
              ? `\n\u0628\u0631\u0627\u06cc \u062c\u0644\u0648\u06af\u06cc\u0631\u06cc \u0627\u0632 \u062c\u0644\u0633\u0647\u200c\u06cc \u0628\u062f\u0648\u0646 \u0627\u062a\u0627\u0642\u060c \u06a9\u0644 \u0633\u0631\u06cc \u0644\u063a\u0648 \u0634\u062f. \u0644\u0637\u0641\u0627\u064b \u0633\u0627\u0639\u062a \u06cc\u0627 \u0627\u062a\u0627\u0642 \u062f\u06cc\u06af\u0631\u06cc \u0627\u0646\u062a\u062e\u0627\u0628 \u06a9\u0646 \u06a9\u0647 \u062f\u0631 \u062a\u0645\u0627\u0645 \u062a\u0627\u0631\u06cc\u062e\u200c\u0647\u0627 \u0622\u0632\u0627\u062f \u0628\u0627\u0634\u062f.`
              : `\n\u26a0\ufe0f \u0647\u0634\u062f\u0627\u0631: \u062a\u0644\u0627\u0634 \u0628\u0631\u0627\u06cc \u0644\u063a\u0648 \u062e\u0648\u062f\u06a9\u0627\u0631 \u0646\u0627\u0645\u0648\u0641\u0642 \u0628\u0648\u062f (${rb.reason}). \u0644\u0637\u0641\u0627\u064b \u062c\u0644\u0633\u0647 \u0631\u0627 \u062f\u0633\u062a\u06cc \u0628\u0631\u0631\u0633\u06cc \u0648 \u062d\u0630\u0641 \u06a9\u0646.`;
            return msg;
          }
          return null;
        };

        const unknownMsg = (list) => `\u274c \u0627\u06cc\u0646 \u0622\u062f\u0631\u0633\u200c\u0647\u0627 \u062f\u0631 Exchange \u067e\u06cc\u062f\u0627 \u0646\u0634\u062f\u0646\u062f: ${list.join("\u060c ")}\n\n\u0627\u06cc\u0645\u06cc\u0644 \u0631\u0627 \u0627\u0635\u0644\u0627\u062d \u06a9\u0646 (\u06cc\u0627 \u0628\u0627 search_user \u067e\u06cc\u062f\u0627 \u06a9\u0646) \u0648 \u062f\u0648\u0628\u0627\u0631\u0647 \u062a\u0644\u0627\u0634 \u06a9\u0646. \u0686\u06cc\u0632\u06cc \u062b\u0628\u062a \u0646\u0634\u062f.`;

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
            let msg = `\u274c \u0627\u06cc\u0646 \u062c\u0644\u0633\u0647\u200c\u06cc \u062a\u06a9\u0631\u0627\u0631\u0634\u0648\u0646\u062f\u0647 \u062b\u0628\u062a \u0646\u0634\u062f \u0686\u0648\u0646 \u062f\u0631 ${conflicts.length} \u0645\u0648\u0631\u062f \u0627\u0632 ${checkedCount} \u062c\u0644\u0633\u0647\u060c \u0627\u062a\u0627\u0642 \u06cc\u0627 \u0634\u0631\u06a9\u062a\u200c\u06a9\u0646\u0646\u062f\u0647 \u062f\u0631 \u0633\u0627\u0639\u062a ${hhmm} \u0645\u0634\u063a\u0648\u0644 \u0627\u0633\u062a:\n`;
            conflicts.slice(0, 15).forEach(cf => { msg += `  \ud83d\udd34 ${cf.date}: ${cf.busy.map(e => e.includes("room-") ? getRoomDisplayName(e) : e).join("\u060c ")}\n`; });
            if (conflicts.length > 15) msg += `  \u2026 \u0648 ${conflicts.length - 15} \u0645\u0648\u0631\u062f \u062f\u06cc\u06af\u0631\n`;
            msg += `\n\u0628\u0631\u0627\u06cc \u0631\u0632\u0631\u0648 \u0645\u0648\u0641\u0642 \u0633\u0631\u06cc\u060c \u0628\u0627\u06cc\u062f \u0633\u0627\u0639\u062a \u06cc\u0627 \u0631\u0648\u0632\u06cc \u0627\u0646\u062a\u062e\u0627\u0628 \u0634\u0648\u062f \u06a9\u0647 \u062f\u0631 \u062a\u0645\u0627\u0645 \u062a\u0627\u0631\u06cc\u062e\u200c\u0647\u0627 \u0622\u0632\u0627\u062f \u0628\u0627\u0634\u062f.`;
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
          return { content: [{ type: "text", text: `\u2705 \u062c\u0644\u0633\u0647\u200c\u06cc \u062a\u06a9\u0631\u0627\u0631\u0634\u0648\u0646\u062f\u0647 "${subject}" \u062b\u0628\u062a \u0634\u062f! (${occDates.length} \u062c\u0644\u0633\u0647)\n\ud83d\udcc5 \u0627\u0632 ${describeDate(date)} \u0633\u0627\u0639\u062a ${start_time} \u062a\u0627 ${endTimeStr.substring(0,5)} (\u0627\u06cc\u0631\u0627\u0646)\n\ud83c\udfe2 \u0627\u062a\u0627\u0642: ${room_email ? getRoomDisplayName(room_email) : "\u0628\u062f\u0648\u0646 \u0627\u062a\u0627\u0642"}\n\ud83d\udc65 \u0634\u0631\u06a9\u062a\u200c\u06a9\u0646\u0646\u062f\u06af\u0627\u0646: ${attendee_emails.join(", ") || "\u0628\u062f\u0648\u0646 \u0634\u0631\u06a9\u062a\u200c\u06a9\u0646\u0646\u062f\u0647"}` }] };
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
          let out = `\u274c \u062a\u063a\u06cc\u06cc\u0631 \u0648\u0636\u0639\u06cc\u062a: \u0627\u06cc\u0646 \u0632\u0645\u0627\u0646 \u062f\u06cc\u06af\u0631 \u0622\u0632\u0627\u062f \u0646\u06cc\u0633\u062a.\n\n\u0628\u06cc\u0632\u06cc:\n`;
          freshBusy.forEach(email => { out += `  \ud83d\udd34 ${email.includes("room-") ? getRoomDisplayName(email) : email}\n`; });
          const newFreeSlots = findFreeSlots(date, (() => { const pa = {}; for (const e of Object.keys(freshAvail).filter(e => !e.includes("room-"))) pa[e] = freshAvail[e] || []; return pa; })());
          if (newFreeSlots.length) {
            out += `\n\u2705 \u0627\u0633\u0644\u0627\u062a\u200c\u0647\u0627\u06cc \u0622\u0632\u0627\u062f:\n`;
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
        return { content: [{ type: "text", text: `\u2705 \u062c\u0644\u0633\u0647 "${subject}" \u062b\u0628\u062a \u0634\u062f!\n\ud83d\udcc5 ${describeDate(date)} \u0633\u0627\u0639\u062a ${start_time} \u062a\u0627 ${endTimeStr.substring(0,5)} (\u0627\u06cc\u0631\u0627\u0646)\n\ud83c\udfe2 \u0627\u062a\u0627\u0642: ${room_email ? getRoomDisplayName(room_email) : "\u0628\u062f\u0648\u0646 \u0627\u062a\u0627\u0642"}\n\ud83d\udc65 \u0634\u0631\u06a9\u062a\u200c\u06a9\u0646\u0646\u062f\u06af\u0627\u0646: ${attendee_emails.join(", ") || "\u0628\u062f\u0648\u0646 \u0634\u0631\u06a9\u062a\u200c\u06a9\u0646\u0646\u062f\u0647"}` }] };
      } catch (e) { return { content: [{ type: "text", text: `\u274c ${e.message}` }] }; }
    }
  );


  // ── list_events ──
  server.tool("list_events",
    "List your calendar events.",
    { session_token: z.string().optional(), start: z.string().describe("ALWAYS use full datetime: 2026-06-20T00:00:00"), end: z.string().describe("ALWAYS use full datetime: 2026-06-20T23:59:59") },
    async ({ session_token, start, end }) => {
      const isRealToken = (t) => t && (t.startsWith("eyJ") || /^[0-9a-f-]{36}$/.test(t));
    const _resolvedToken = (isRealToken(session_token) ? session_token : null) || getAutoToken();
    const payload = await validateJWT(_resolvedToken);
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
            if (req.length) line += `   👥 شرکت‌کنندگان: ${req.map(a => `${a.name} <${a.email}>`).join(", ")}\n`;
            if (opt.length) line += `   👁 اختیاری: ${opt.map(a => `${a.name} <${a.email}>`).join(", ")}\n`;
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
    "Delete a calendar event. CRITICAL: If event is part of a recurring series, ALWAYS ask user first: فقط این جلسه، این و بعدی‌ها، یا کل سری؟ — NEVER auto-delete series without asking. For single non-recurring events: delete immediately after user confirmation.",
    {
      session_token: z.string().optional().optional(),
      item_id: z.string(),
      change_key: z.string(),
      recurrence_action: z.enum(["AllOccurrences","SpecifiedOccurrenceOnly","AllFollowingOccurrences"]).default("AllOccurrences").describe("AllOccurrences=entire series (default), SpecifiedOccurrenceOnly=just this one, AllFollowingOccurrences=this and future")
    },
    async ({ session_token, item_id, change_key, recurrence_action }) => {
      const isRealToken = (t) => t && (t.startsWith("eyJ") || /^[0-9a-f-]{36}$/.test(t));
    const _resolvedToken = (isRealToken(session_token) ? session_token : null) || getAutoToken();
    const payload = await validateJWT(_resolvedToken);
      if (!payload) return { content: [{ type: "text", text: "❌ Session expired. Please try again." }] };
      const userEmail = payload.email;
      try {
        await deleteEvent(userEmail, { itemId: item_id, changeKey: change_key, affectedOccurrences: recurrence_action || "AllOccurrences" });
        const msg = recurrence_action === "SpecifiedOccurrenceOnly" ? "✅ این جلسه حذف شد." :
                    recurrence_action === "AllFollowingOccurrences" ? "✅ این جلسه و تمام جلسات بعدی حذف شدند." :
                    "✅ کل سری جلسات حذف شد.";
        return { content: [{ type: "text", text: msg }] };
      } catch (e) { return { content: [{ type: "text", text: `❌ ${e.message}` }] }; }
    }
  );

  // ── update_event ──
  server.tool("update_event",
    "Update an event. IMPORTANT: Always call list_events first to get a fresh change_key before updating — stale change_keys will silently fail. For time changes: check_availability first for all attendees+room. attendee_emails replaces ALL attendees (include room email separately via room_email).",
    {
      session_token: z.string().optional().optional(), item_id: z.string(), change_key: z.string(),
      attendee_emails: z.array(z.string()).optional().describe("Full replacement list — replaces ALL existing attendees"),
      room_email: z.string().optional().describe("New room email e.g. room-s5@example.com — sets location and room attendee"),
      subject: z.string().optional(),
      start: z.string().optional().describe("New start time ISO8601 Iran local time"),
      end: z.string().optional().describe("New end time ISO8601 Iran local time"),
      body: z.string().optional(),
      recurrence_action: z.enum(['AllOccurrences','SpecifiedOccurrenceOnly']).default('AllOccurrences').describe("AllOccurrences=update entire series, SpecifiedOccurrenceOnly=only this occurrence")
    },
    async ({ session_token, item_id, change_key, subject, start, end, body, attendee_emails, room_email, recurrence_action }) => {
      const isRealToken = (t) => t && (t.startsWith("eyJ") || /^[0-9a-f-]{36}$/.test(t));
    const _resolvedToken = (isRealToken(session_token) ? session_token : null) || getAutoToken();
    const payload = await validateJWT(_resolvedToken);
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
            return { content: [{ type: "text", text: `❌ ایمیل اتاق نامعتبر: "${room_email}"\n\nاتاق‌های موجود:\n${roomList}` }] };
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
        if (subject) changed.push(`موضوع: ${subject}`);
        if (start) changed.push(`شروع: ${start}`);
        if (end) changed.push(`پایان: ${end}`);
        if (room_email) changed.push(`اتاق جدید: ${room_email}`);
        if (body) changed.push("توضیحات آپدیت شد");
        return { content: [{ type: "text", text: `✅ جلسه آپدیت شد.\n${changed.join("\n")}` }] };
      } catch (e) { return { content: [{ type: "text", text: `❌ ${e.message}` }] }; }
    }
  );

  // ── book_for_group ──
  server.tool("book_for_group",
    "Book a meeting for an entire AD group. Expands the group, checks availability for all members + room, shows who's busy, and books only when confirmed=true is passed. Flow: first call with confirmed=false to show availability report, then call again with confirmed=true after user agrees.",
    {
      session_token: z.string().optional().optional(),
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
    async ({ session_token, group_email: _gep, group_name, subject, date, start_time, duration_minutes, room_email, body, confirmed }) => {
      const group_email = _gep || group_name;
      const isRealToken = (t) => t && (t.startsWith("eyJ") || /^[0-9a-f-]{36}$/.test(t));
    const _resolvedToken = (isRealToken(session_token) ? session_token : null) || getAutoToken();
    const payload = await validateJWT(_resolvedToken);
      if (!payload) return { content: [{ type: "text", text: "❌ Session expired. Please try again — a browser will open to log in automatically." }] };
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
        out += `📅 ${date} ${start_time} (${duration_minutes} دقیقه)\n\n`;

        if (busyMembers.length === 0 && !roomBusy) {
          out += `✅ همه اعضا و اتاق در این زمان آزاد هستند.\n`;
        } else {
          if (busyMembers.length > 0) {
            out += `🔴 مشغول (${busyMembers.length} نفر):\n`;
            busyMembers.forEach(e => {
              const name = members.find(m => m.email === e)?.name || e;
              const busyTimes = (avail[e] || []).map(b => `${formatDateTime(b.start)}→${formatDateTime(b.end)}`).join(", ");
              out += `  • ${name} <${e}>: ${busyTimes}\n`;
            });
          }
          if (roomBusy) {
            const roomTimes = (avail[room_email] || []).map(b => `${formatDateTime(b.start)}→${formatDateTime(b.end)}`).join(", ");
            out += `🔴 اتاق مشغول: ${roomTimes}\n`;
          }
          const freeMembers = memberEmails.filter(e => !busyMembers.includes(e));
          if (freeMembers.length > 0) {
            out += `\n✅ آزاد (${freeMembers.length} نفر):\n`;
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
            out += `\n📅 اسلات‌های مشترک آزاد در ${date}:\n`;
            freeSlots.forEach(sl => { out += `  • ${formatSlot(sl)}\n`; });
          } else {
            out += `\n❌ هیچ اسلات مشترک آزادی در ${date} پیدا نشد.\n`;
          }
        }

        if (!confirmed) {
          out += `\nبرای رزرو این جلسه برای همه اعضا، تایید کنید تا با confirmed=true دوباره فراخوانی شود.`;
          return { content: [{ type: "text", text: out }] };
        }

        // Step 6: confirmed=true — do double fresh-check then book
        const freshAvail = await getAvailability( allEmails, `${date}T00:00:00`, `${date}T23:59:59`);
        const freshBusy = allEmails.filter(e => isBusy(requestedSlot, freshAvail[e] || []));
        if (freshBusy.length > 0) {
          let errOut = `❌ تغییر وضعیت: این زمان دیگر آزاد نیست.\n\nمشغول:\n`;
          freshBusy.forEach(e => {
            const name = members.find(m => m.email === e)?.name || e;
            errOut += `  🔴 ${name} <${e}>\n`;
          });
          const newFreeSlots = findFreeSlots(date, (() => { const pa = {}; for (const e of Object.keys(freshAvail).filter(e => !e.includes("room-"))) pa[e] = freshAvail[e] || []; return pa; })());
          if (newFreeSlots.length) {
            errOut += `\n✅ اسلات‌های آزاد:\n`;
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
        return { content: [{ type: "text", text: `✅ جلسه "${subject}" برای گروه ثبت شد!\n📅 ${date} ساعت ${start_time} تا ${endHStr}:${endMStr} (ایران)\n🏢 اتاق: ${room_email}\n👥 اعضا (${members.length}): ${members.map(m => m.name).join(", ")}` }] };
      } catch (e) { return { content: [{ type: "text", text: `❌ ${e.message}` }] }; }
    }
  );


  // ── list_emails ──
  server.tool("list_emails",
    "List emails from inbox. Filter by unread, sender name/email, or date.",
    {
      session_token: z.string().optional().optional(),
      unread_only: z.boolean().optional(),
      from: z.string().optional().describe("Sender name or email to filter by"),
      date: z.string().optional().describe("Date filter e.g. 2026-04-25"),
      max_count: z.number().optional()
    },
    async ({ session_token, unread_only, from: fromFilter, date, max_count }) => {
      const isRealToken = (t) => t && (t.startsWith("eyJ") || /^[0-9a-f-]{36}$/.test(t));
    const _resolvedToken = (isRealToken(session_token) ? session_token : null) || getAutoToken();
    const payload = await validateJWT(_resolvedToken);
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
    { session_token: z.string().optional().optional(), item_id: z.string() },
    async ({ session_token, item_id }) => {
      const isRealToken = (t) => t && (t.startsWith("eyJ") || /^[0-9a-f-]{36}$/.test(t));
    const _resolvedToken = (isRealToken(session_token) ? session_token : null) || getAutoToken();
    const payload = await validateJWT(_resolvedToken);
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
    "Send an email. Supports To, CC, BCC, subject and body.",
    {
      session_token: z.string().optional().optional(),
      to: z.array(z.string()),
      cc: z.array(z.string()).optional(),
      bcc: z.array(z.string()).optional(),
      subject: z.string(),
      body: z.string(),
      direction: z.enum(['auto','rtl','ltr']).optional().describe("Text direction: auto=detect, rtl=Persian/Arabic, ltr=English")
    },
    async ({ session_token, to, cc, bcc, subject, body, direction }) => {
      const isRealToken = (t) => t && (t.startsWith("eyJ") || /^[0-9a-f-]{36}$/.test(t));
    const _resolvedToken = (isRealToken(session_token) ? session_token : null) || getAutoToken();
    const payload = await validateJWT(_resolvedToken);
      if (!payload) return { content: [{ type: "text", text: "❌ Session expired. Please try again — a browser will open to log in automatically." }] };
      const userEmail = payload.email;
      const userName = payload.preferred_username;
      try {
        await sendEmailEWS(userEmail, { to, cc: cc || [], bcc: bcc || [], subject, body, direction: direction || 'auto' });
        let out = `✅ Email sent!\n📧 To: ${to.join(", ")}`;
        if (cc?.length) out += `\n📋 CC: ${cc.join(", ")}`;
        out += `\n📌 Subject: ${subject}`;
        return { content: [{ type: "text", text: out }] };
      } catch (e) { return { content: [{ type: "text", text: `❌ ${e.message}` }] }; }
    }
  );

  // ── reply_email ──
  server.tool("reply_email",
    "Reply to an existing email by ID.",
    {
      session_token: z.string().optional().optional(),
      item_id: z.string(),
      body: z.string(),
      reply_all: z.boolean().optional(),
      direction: z.enum(['auto','rtl','ltr']).optional().describe("Text direction: auto=detect, rtl=Persian/Arabic, ltr=English")
    },
    async ({ session_token, item_id, body, reply_all, direction }) => {
      const isRealToken = (t) => t && (t.startsWith("eyJ") || /^[0-9a-f-]{36}$/.test(t));
    const _resolvedToken = (isRealToken(session_token) ? session_token : null) || getAutoToken();
    const payload = await validateJWT(_resolvedToken);
      if (!payload) return { content: [{ type: "text", text: "❌ Session expired. Please try again — a browser will open to log in automatically." }] };
      const userEmail = payload.email;
      const userName = payload.preferred_username;
      try {
        await replyEmailEWS(userEmail, { itemId: item_id, body, replyAll: reply_all || false, direction: direction || 'auto' });
        return { content: [{ type: "text", text: `✅ Reply sent${reply_all ? " (reply all)" : ""}.` }] };
      } catch (e) { return { content: [{ type: "text", text: `❌ ${e.message}` }] }; }
    }
  );


  // ── get_attachments ──
      server.tool("get_attachments",
    "Download email attachments and return browser-ready download links (valid 10 min).",
    { session_token: z.string().optional().optional(), item_id: z.string() },
    async ({ session_token, item_id }) => {
      const isRealToken = (t) => t && (t.startsWith("eyJ") || /^[0-9a-f-]{36}$/.test(t));
    const _resolvedToken = (isRealToken(session_token) ? session_token : null) || getAutoToken();
    const payload = await validateJWT(_resolvedToken);
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
            const xml = `<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"><soap:Body><m:GetAttachment><m:AttachmentShape/><m:AttachmentIds><t:AttachmentId Id="${a.attId}"/></m:AttachmentIds></m:GetAttachment></soap:Body></soap:Envelope>`;
            const response = await ewsRequest(SVC_USERNAME, SVC_PASSWORD, xml, userEmail);
            const content64 = (response.match(/<(?:[^:>]+:)?Content>([\s\S]+?)<\/(?:[^:>]+:)?Content>/) || [])[1];
            if (!content64) return `${i+1}. ${a.name} — could not download`;
            const buffer = Buffer.from(content64.replace(/\s/g, ''), 'base64');
            const shortId = randomUUID();
            const tmpFile = `/tmp/exchange-att-${shortId}`;
            writeFileSync(tmpFile, buffer);
            // Auto-delete after 10 min
            setTimeoutP(() => { try { unlinkSync(tmpFile); unlinkSync(tmpFile + '.meta'); } catch {} }, 600000);
            // Store metadata
            const meta = JSON.stringify({ name: a.name, contentType: a.contentType || 'application/octet-stream' });
            writeFileSync(tmpFile + '.meta', meta);
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
    "Logout and invalidate session.",
    { session_token: z.string().optional() },
    async ({ session_token }) => {
      return { content: [{ type: "text", text: "✅ خارج شدی." }] };
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
    // Extract Bearer token from Authorization header (Claude Code OAuth flow)
    const authHeader = req.headers["authorization"];
    let bearerToken = null;

    if (authHeader && authHeader.startsWith("Bearer ")) {
      bearerToken = authHeader.substring(7);
      const payload = await validateJWT(bearerToken).catch(() => null);
      if (!payload) {
        res.writeHead(401, {
          "WWW-Authenticate": `Bearer realm="${MCP_SERVER_URL}", resource_metadata="${MCP_SERVER_URL}/.well-known/oauth-protected-resource"`,
          "Content-Type": "application/json"
        });
        res.end(JSON.stringify({ error: "invalid_token", error_description: "Token is invalid or expired" }));
        return;
      }
      req._bearerToken = bearerToken;
    } else {
      // No Bearer token — check if this session already has a token stored
      const existingSessionId = req.headers["mcp-session-id"];
      const storedToken = existingSessionId ? mcpTransports.get(existingSessionId + '_token') : null;
      if (storedToken) {
        bearerToken = storedToken;
      }
      // Only block completely new sessions with no token at all
      // DXT sends session_token in tool args — always let through
      // Claude Code OAuth sends Bearer header — handled above
    }

    const sessionId = req.headers["mcp-session-id"];
    // Unknown or expired session id (after a restart or idle eviction): answer 404 as the MCP spec
    // requires, so clients start a new session instead of failing with 400 "Server not initialized".
    if (sessionId && !mcpTransports.has(sessionId)) {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32001, message: "Session not found" }, id: null }));
      return;
    }
    if (sessionId) sessionLastSeen.set(sessionId, Date.now());
    // Store bearer tokens per session
    if (bearerToken && sessionId) mcpTransports.set(sessionId + '_token', bearerToken);
    const effectiveToken = bearerToken || (sessionId ? mcpTransports.get(sessionId + '_token') : null);

    let transport = sessionId ? mcpTransports.get(sessionId) : null;
    if (!transport) {
      const sessionRef = { id: null };
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        enableJsonResponse: true,
        onsessioninitialized: (id) => {
          sessionRef.id = id;
          sessionLastSeen.set(id, Date.now());
          mcpTransports.set(id, transport);
          if (effectiveToken) {
            mcpTransports.set(id + '_token', effectiveToken);
            sessionTokenMap.set(id, effectiveToken);
          }
        }
      });
      transport.onclose = () => {
        if (transport.sessionId) {
          sessionLastSeen.delete(transport.sessionId);
          mcpTransports.delete(transport.sessionId);
          mcpTransports.delete(transport.sessionId + '_token');
          sessionTokenMap.delete(transport.sessionId);
        }
      };
      await buildMcpServer(effectiveToken, sessionRef).connect(transport);
    } else if (bearerToken && sessionId) {
      // Token arrived on existing session — update sessionTokenMap
      mcpTransports.set(sessionId + '_token', bearerToken);
      sessionTokenMap.set(sessionId, bearerToken);
    }
    await transport.handleRequest(req, res);
    return;
  }
  res.writeHead(404); res.end("Not found");
});

httpServer.listen(PORT, "127.0.0.1", () => {
  console.log(`✅ Exchange MCP Server v2.0 running on port ${PORT}`);
});
