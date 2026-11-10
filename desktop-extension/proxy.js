// Claude Desktop extension (.mcpb) for microsoft-exchange-2019-on-premises-claude-mcp.
// Runs on the user's computer over stdio and forwards every tool call to your server,
// so it works with a server on an internal network or VPN.
//
// Sign-in: the user's browser goes to your OIDC provider, which redirects to
// <server>/auth/oauth-callback; this proxy then collects the tokens from <server>/auth/poll-token
// with its PKCE verifier and sends the access token to the server in the Authorization header
// of every request. The OIDC endpoints and client id are read from the server
// (/.well-known/oauth-authorization-server and /oauth/register), so the only setting is the server URL.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import fs from "fs";
import path from "path";
import https from "https";
import http from "http";
import crypto from "crypto";
import { execFile } from "child_process";
import { M } from "./messages.js";

const VERSION = "2.1.1";
// Settings come from manifest.json (user_config or literal env values). An empty field, or a
// placeholder Claude Desktop did not fill in, counts as unset.
const setting = name => { const v = (process.env[name] || "").trim(); return v.includes("${") ? "" : v; };
const SERVER_URL = setting("EXCHANGE_MCP_URL").replace(/\/+$/, "").replace(/\/mcp$/, "");
const MCP_URL = `${SERVER_URL}/mcp`;
// Tokens travel to this server, so plain http is allowed only for a server on this computer.
const SERVER_OK = (() => {
  try {
    const u = new URL(SERVER_URL);
    return u.protocol === "https:" || (u.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname));
  } catch { return false; }
})();
const CALLBACK_URL = `${SERVER_URL}/auth/oauth-callback`;
const POLL_URL = `${SERVER_URL}/auth/poll-token`;

const TOKEN_DIR = path.join(process.env.APPDATA || process.env.HOME || ".", ".claude");
const TOKEN_FILE = path.join(TOKEN_DIR, "exchange-mcp-token.json");
const STATE_FILE = path.join(TOKEN_DIR, "exchange-mcp-oauth-state.json");

let sessionId = null;
let tokenData = null;
let authInProgress = false;

// ─── Discovery: OIDC endpoints + client from the server ──────────────────────
let oidc = null; // { authUrl, tokenUrl, logoutUrl, clientId, clientSecret }
async function getOidc() {
  if (oidc) return oidc;
  if (!SERVER_URL) throw new Error("not configured");
  if (!SERVER_OK) throw new Error("the server URL must start with https://");
  const meta = await httpJson("GET", `${SERVER_URL}/.well-known/oauth-authorization-server`);
  const reg = await httpJson("POST", `${SERVER_URL}/oauth/register`, "{}", "application/json");
  if (!meta.authorization_endpoint || !meta.token_endpoint || !reg.client_id) throw new Error("incomplete OAuth metadata");
  oidc = {
    authUrl: meta.authorization_endpoint,
    tokenUrl: meta.token_endpoint,
    // Keycloak-shaped providers: .../protocol/openid-connect/{auth,token,logout}
    logoutUrl: meta.token_endpoint.replace(/\/token$/, "/logout"),
    clientId: reg.client_id,
    clientSecret: reg.client_secret || "",
  };
  return oidc;
}
const clientParams = o => `client_id=${encodeURIComponent(o.clientId)}` + (o.clientSecret ? `&client_secret=${encodeURIComponent(o.clientSecret)}` : "");

// ─── PKCE helpers ─────────────────────────────────────────────────────────────
function generatePKCE() {
  const verifier = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

// The sign-in URL comes from the server's metadata: accept only http(s) URLs. href is
// percent-encoded, so it holds no quote; on Windows the quotes keep cmd from reading & in the query.
function openBrowser(url) {
  const u = new URL(url);
  if (u.protocol !== "https:" && u.protocol !== "http:") throw new Error("refusing to open a non-http(s) URL");
  if (/["^\r\n]/.test(u.href)) throw new Error("refusing to open an unsafe URL");
  if (process.platform === "win32") execFile("cmd.exe", ["/c", `start "" "${u.href}"`], { windowsVerbatimArguments: true, windowsHide: true }, () => {});
  else execFile(process.platform === "darwin" ? "open" : "xdg-open", [u.href], () => {});
}

// ─── HTTP ─────────────────────────────────────────────────────────────────────
function httpJson(method, url, body = null, contentType = "application/x-www-form-urlencoded") {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const lib = u.protocol === "http:" ? http : https;
    const headers = body != null ? { "Content-Type": contentType, "Content-Length": Buffer.byteLength(body) } : {};
    const req = lib.request({ hostname: u.hostname, port: u.port || undefined, path: u.pathname + u.search, method, headers }, res => {
      let d = ""; res.on("data", c => d += c); res.on("end", () => {
        try { resolve(JSON.parse(d)); } catch { reject(new Error(`HTTP ${res.statusCode}`)); }
      });
    });
    req.setTimeout(30000, () => req.destroy(new Error("timeout")));
    req.on("error", reject);
    if (body != null) req.write(body);
    req.end();
  });
}

// ─── Token Management ─────────────────────────────────────────────────────────
function loadToken() {
  try { return JSON.parse(fs.readFileSync(TOKEN_FILE, "utf8")); }
  catch { return null; }
}

function saveToken(data) {
  if (!fs.existsSync(TOKEN_DIR)) fs.mkdirSync(TOKEN_DIR, { recursive: true });
  fs.writeFileSync(TOKEN_FILE, JSON.stringify(data), { encoding: "utf8", mode: 0o600 });
  sessionId = null;
}

function isExpired(data) {
  return !data || !data.expires_at || Date.now() > data.expires_at - 30000;
}

// Read the email claim from our own access token (no verification needed here — the server verifies it).
function emailFromJwt(t) {
  try {
    const p = JSON.parse(Buffer.from(String(t).split(".")[1], "base64url").toString("utf8"));
    return p.email || null;
  } catch { return null; }
}

// Ask the server for the tokens of a sign-in that finished in the browser
async function pollForToken() {
  try {
    if (!fs.existsSync(STATE_FILE)) return;
    const state = JSON.parse(fs.readFileSync(STATE_FILE, "utf8"));
    if (!state || Date.now() - state.created > 300000) {
      try { fs.unlinkSync(STATE_FILE); } catch {}
      return;
    }
    const o = await getOidc();
    const result = await httpJson("POST", POLL_URL,
      `state=${encodeURIComponent(state.state)}&verifier=${encodeURIComponent(state.verifier)}&${clientParams(o)}&redirect_uri=${encodeURIComponent(CALLBACK_URL)}`);
    if (result && result.access_token) {
      const tokenObj = { access_token: result.access_token, refresh_token: result.refresh_token, expires_at: Date.now() + result.expires_in * 1000 };
      saveToken(tokenObj);
      tokenData = tokenObj;
      try { fs.unlinkSync(STATE_FILE); } catch {}
      console.error("[OAuth] Signed in");
    }
  } catch (e) { console.error("[OAuth] Poll error:", e.message); }
}
pollForToken();

async function refreshAccessToken(refreshToken) {
  const o = await getOidc();
  const data = await httpJson("POST", o.tokenUrl,
    `${clientParams(o)}&grant_type=refresh_token&refresh_token=${encodeURIComponent(refreshToken)}`);
  if (!data.access_token) throw new Error("Refresh failed");
  const tokenObj = {
    access_token: data.access_token,
    refresh_token: data.refresh_token || refreshToken,
    expires_at: Date.now() + data.expires_in * 1000
  };
  saveToken(tokenObj);
  return tokenObj;
}

async function startOAuthFlow() {
  if (authInProgress) return;
  authInProgress = true;
  try {
    const o = await getOidc();
    const { verifier, challenge } = generatePKCE();
    const state = crypto.randomBytes(16).toString("hex");
    // Save verifier+state so the proxy can collect the tokens after the redirect
    if (!fs.existsSync(TOKEN_DIR)) fs.mkdirSync(TOKEN_DIR, { recursive: true });
    fs.writeFileSync(STATE_FILE, JSON.stringify({ verifier, state, created: Date.now() }), { mode: 0o600 });
    const authUrl = `${o.authUrl}?` +
      `client_id=${encodeURIComponent(o.clientId)}&response_type=code&redirect_uri=${encodeURIComponent(CALLBACK_URL)}` +
      `&code_challenge=${challenge}&code_challenge_method=S256&state=${state}&scope=openid+profile+email`;
    openBrowser(authUrl);
  } finally {
    authInProgress = false;
  }
}

// Open the browser and wait up to 3 minutes for the sign-in to finish
async function signInAndWait() {
  await startOAuthFlow();
  for (let waited = 0; waited < 180; waited += 2) {
    await new Promise(r => setTimeout(r, 2000));
    await pollForToken();
    const t = loadToken();
    if (t && !isExpired(t)) return t;
  }
  return null;
}

// ─── MCP Remote Call ──────────────────────────────────────────────────────────
const REQUEST_TIMEOUT_MS = 90000;

function mcpRequest(body, sid, token) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const u = new URL(MCP_URL);
    const lib = u.protocol === "http:" ? http : https;
    const headers = {
      "Content-Type": "application/json",
      "Accept": "application/json, text/event-stream",
      "Content-Length": Buffer.byteLength(data)
    };
    if (sid) headers["mcp-session-id"] = sid;
    if (token) headers["Authorization"] = `Bearer ${token}`;
    const req = lib.request({
      hostname: u.hostname, port: u.port || undefined, path: u.pathname,
      method: "POST", headers
    }, res => {
      let raw = "";
      res.on("data", d => raw += d);
      res.on("end", () => {
        const sessionIdHeader = res.headers["mcp-session-id"];
        let parsed = {};
        for (const line of raw.split("\n")) {
          if (line.startsWith("data: ")) { try { parsed = JSON.parse(line.slice(6)); } catch {} }
          else if (line.startsWith("{")) { try { parsed = JSON.parse(line); } catch {} }
        }
        if (sessionIdHeader) parsed._sessionId = sessionIdHeader;
        parsed._status = res.statusCode;
        resolve(parsed);
      });
    });
    // Never hang Claude Desktop forever if the server or a gateway stalls
    req.setTimeout(REQUEST_TIMEOUT_MS, () => req.destroy(new Error(`timeout after ${REQUEST_TIMEOUT_MS / 1000}s`)));
    req.on("error", reject);
    req.write(data);
    req.end();
  });
}

// Safe to send twice: read-only tools, and previews (confirmed !== true) of tools that have a confirm gate.
const READ_ONLY_TOOLS = new Set(["get_current_time", "list_rooms", "search_user", "resolve_team", "get_manager", "get_direct_reports", "resolve_group", "check_availability", "list_events", "list_emails", "read_email", "get_attachments"]);
const GATED_TOOLS = new Set(["smart_schedule", "book_for_group", "book_meeting_with_team", "book_meeting_with_direct_reports", "send_email_to_team"]);
const INIT_BODY = { jsonrpc: "2.0", id: 0, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "exchange-mcp-desktop-extension", version: VERSION } } };
const text = t => ({ content: [{ type: "text", text: t }] });

async function callTool(name, args) {
  if (!SERVER_URL) return text(M.notConfigured);
  try { await getOidc(); } catch (e) { return text(M.discoveryFailed(e.message)); }

  let data = tokenData || loadToken();

  // No token yet: collect a finished sign-in, or open the browser and wait for one
  if (!data) {
    await pollForToken();
    const fresh = loadToken();
    if (fresh && !isExpired(fresh)) data = fresh;
    else data = await signInAndWait();
    if (!data) return text(M.browserOpened);
    tokenData = data;
  }

  // Token expired: refresh it, or sign in again
  if (isExpired(data)) {
    if (data.refresh_token) {
      try { data = await refreshAccessToken(data.refresh_token); tokenData = data; }
      catch {
        tokenData = null;
        const fresh = loadToken();
        data = fresh && !isExpired(fresh) ? fresh : await signInAndWait();
        if (!data) return text(M.browserOpened);
        tokenData = data;
      }
    } else {
      startOAuthFlow().catch(() => {});
      return text(M.loginRequired);
    }
  }

  let token = data.access_token;
  if (!token) return text(M.authFailed);

  // Team tools: when the model omits "who", default to the signed-in user (email claim of our own token).
  const DEFAULT_SELF = { resolve_team: "user_email", book_meeting_with_team: "user_email", send_email_to_team: "manager_email" };
  if (DEFAULT_SELF[name] && !args[DEFAULT_SELF[name]]) {
    const me = emailFromJwt(token);
    if (me) args = { ...args, [DEFAULT_SELF[name]]: me };
  }

  const safeToRepeat = READ_ONLY_TOOLS.has(name) || (GATED_TOOLS.has(name) && args.confirmed !== true);

  const callOnce = async () => {
    if (!sessionId) {
      try {
        const init = await mcpRequest(INIT_BODY, null, token);
        sessionId = init._sessionId || null;
        if (sessionId) await mcpRequest({ jsonrpc: "2.0", method: "notifications/initialized" }, sessionId, token).catch(() => {});
      } catch (e) { return { _notSent: true, _transportError: e.message }; }
    }
    try {
      return await mcpRequest({ jsonrpc: "2.0", id: Date.now(), method: "tools/call", params: { name, arguments: args } }, sessionId, token);
    } catch (e) { return { _transportError: e.message }; }
  };
  // The server refused the request BEFORE running it (session unknown after a restart/eviction, or not
  // initialised) — retrying on a fresh session is always safe.
  const sessionRejected = r => !r.result && r.error && (r._status === 404 || r._status === 400 || r.error.code === -32001 || r.error.code === -32000);

  let result = await callOnce();
  if (result._notSent || sessionRejected(result) || (!result.result && !result.error && safeToRepeat)) {
    sessionId = null;
    result = await callOnce();
  }
  // The server did not accept our token (session ended at the provider, settings changed):
  // refresh it once and retry; if that fails too, sign in again.
  if (result._status === 401) {
    sessionId = null;
    try {
      data = await refreshAccessToken(data.refresh_token); tokenData = data; token = data.access_token;
      result = await callOnce();
    } catch { result = { _status: 401 }; }
    if (result._status === 401) {
      tokenData = null;
      try { fs.unlinkSync(TOKEN_FILE); } catch {}
      startOAuthFlow().catch(() => {});
      return text(M.loginRequired);
    }
  }
  if (result._status === 429) return text(M.tooManyRequests);
  if (result.result) return result.result;
  if (result.error) return text(`❌ ${result.error.message}`);

  // No answer (gateway error, timeout, dropped connection). For a real booking / email / delete the server
  // may already have acted, so never retry blindly — a second attempt could create a duplicate.
  sessionId = null;
  const why = result._transportError || `HTTP ${result._status || "?"}`;
  if (result._notSent) return text(M.notSent(why));
  return text(safeToRepeat ? M.noAnswerSafe(why) : M.noAnswerUnsafe(why));
}

// ─── MCP Server ───────────────────────────────────────────────────────────────
const server = new McpServer({ name: "exchange-2019", version: VERSION });

server.tool("logout", "Log out. After calling this tool, respond ONLY with the tool result text, nothing else.", {},
  async () => {
    const data = tokenData || loadToken();
    const refreshToken = data && data.refresh_token;
    tokenData = null;
    try { fs.unlinkSync(TOKEN_FILE); } catch {}
    sessionId = null;
    // End the session at the OIDC provider too
    if (refreshToken) {
      try {
        const o = await getOidc();
        await httpJson("POST", o.logoutUrl, `${clientParams(o)}&refresh_token=${encodeURIComponent(refreshToken)}`);
      } catch {}
    }
    return text(M.loggedOut);
  });

server.tool("get_current_time", "Get the current date and time in the server's timezone.", {},
  async () => callTool("get_current_time", {}));

server.tool("list_rooms", "List available meeting rooms.", { filter: z.string().optional() },
  async (args) => callTool("list_rooms", args));

server.tool("search_user", "Search for a user by name or email.", { query: z.string() },
  async (args) => callTool("search_user", args));

server.tool("resolve_team",
  "Find all teammates of a person by looking up their manager in AD. Use when user mentions 'my team', 'teammates', or provides a person's email to find their team.",
  { user_email: z.string().optional().describe("Email of the person to find teammates for (omit = the logged-in user)") },
  async (args) => callTool("resolve_team", args));

server.tool("get_manager",
  "Find the manager of a user. Use for 'who is my manager', 'manager of X'.",
  { user_email: z.string().describe("Email of the user to look up") },
  async (args) => callTool("get_manager", args));

server.tool("get_direct_reports",
  "Find all direct reports (subordinates) of a manager in AD. ALWAYS call this after search_user finds a manager, when user wants to meet or email their team. Triggers: 'people under X', 'X team', 'reports of X'.",
  { manager_email: z.string().describe("Email of the manager") },
  async (args) => callTool("get_direct_reports", args));

server.tool("book_meeting_with_team",
  "Book a meeting with all teammates of a person (same manager in AD). Checks availability first.",
  { user_email: z.string().optional().describe("Person whose teammates (same manager) are invited (omit = the logged-in user)"), subject: z.string(), date: z.string().describe("YYYY-MM-DD"), start_time: z.string().describe("HH:MM"), duration_minutes: z.number(), room_email: z.string().optional(), confirmed: z.boolean().describe("false=preview, true=book") },
  async (args) => callTool("book_meeting_with_team", args));

server.tool("book_meeting_with_direct_reports",
  "Book a meeting with all direct reports of a manager. Use when user wants to meet with a manager's team/subordinates. Checks availability first.",
  { manager_email: z.string().describe("Email of the manager"), subject: z.string(), date: z.string().describe("YYYY-MM-DD"), start_time: z.string().describe("HH:MM"), duration_minutes: z.number(), room_email: z.string().optional(), confirmed: z.boolean().describe("false=preview, true=book") },
  async (args) => callTool("book_meeting_with_direct_reports", args));

server.tool("send_email_to_team",
  "Send an email to all direct reports of a manager in AD.",
  { manager_email: z.string().optional().describe("Manager whose direct reports receive the email (omit = the logged-in user, i.e. your own direct reports)"), subject: z.string(), body: z.string(), confirmed: z.boolean().describe("false=preview, true=send") },
  async (args) => callTool("send_email_to_team", args));

server.tool("resolve_group", "Resolve AD group name or email to get member list. Use when user mentions a team or group.",
  { query: z.string().describe("Group name or email e.g. 'it-team' or 'it-team@example.com'") },
  async (args) => callTool("resolve_group", args));

server.tool("check_availability", "Check free/busy for users and rooms on a date.",
  { emails: z.array(z.string()).describe("Email addresses to check"), date: z.string().describe("Date e.g. 2026-04-28") },
  async (args) => callTool("check_availability", args));

server.tool("smart_schedule", "Check availability and book a meeting — single OR recurring. Returns a preview first (nothing booked); after the user approves, call again with confirmed=true to book. Use the recurrence param for weekly/daily/monthly series — it handles the whole series in one call. Suggests alternatives if busy.",
  { subject: z.string(), date: z.string().describe("Date e.g. 2026-04-28 (series start date if recurring)"), start_time: z.string().describe("Start HH:MM (server timezone)"), duration_minutes: z.number().optional(), attendee_emails: z.array(z.string()).describe("Attendee emails"), room_email: z.string().optional(), recurrence: z.object({ type: z.enum(["daily","weekly","monthly"]), interval: z.number().optional(), end_date: z.string().optional().describe("YYYY-MM-DD"), occurrences: z.number().optional().describe("Number of times to repeat") }).optional().describe("For recurring meetings e.g. {type:'weekly',interval:1,occurrences:4}"), confirmed: z.boolean().optional().describe("false/omitted = preview; true = actually book") },
  async (args) => callTool("smart_schedule", args));

server.tool("book_for_group", "Book a meeting for an entire AD group. Pass group email e.g. it-team@example.com.",
  { group_email: z.string().describe("Group email e.g. it-team@example.com"), subject: z.string(), date: z.string().describe("Date e.g. 2026-04-28"), start_time: z.string().describe("Start HH:MM (server timezone)"), duration_minutes: z.number().optional(), room_email: z.string().optional(), confirmed: z.boolean().optional().describe("Pass true to confirm booking after seeing availability report") },
  async (args) => callTool("book_for_group", args));

server.tool("list_events", "List calendar events.",
  { start: z.string().optional(), end: z.string().optional() },
  async (args) => callTool("list_events", args));

server.tool("update_event", "Update event subject/attendees/room/body. ALWAYS call list_events first to get fresh change_key. attendee_emails replaces ALL attendees — include room via room_email separately. For time changes: check_availability first.",
  { item_id: z.string(), change_key: z.string(), subject: z.string().optional(), start: z.string().optional(), end: z.string().optional(), body: z.string().optional(), room_email: z.string().optional(), attendee_emails: z.array(z.string()).optional().describe("Full replacement list of attendee emails - replaces ALL existing attendees"), recurrence_action: z.enum(["AllOccurrences","SpecifiedOccurrenceOnly"]).optional().describe("AllOccurrences=entire series (default), SpecifiedOccurrenceOnly=this occurrence only") },
  async (args) => callTool("update_event", args));

server.tool("delete_event",
  "Delete a calendar event. For recurring series ALWAYS ask user first: delete only this occurrence, this and future, or entire series.",
  {
    item_id: z.string(),
    change_key: z.string(),
    recurrence_action: z.enum(["AllOccurrences","SpecifiedOccurrenceOnly","AllFollowingOccurrences"]).optional().describe("AllOccurrences=entire series (default), SpecifiedOccurrenceOnly=just this one, AllFollowingOccurrences=this and future")
  },
  async (args) => callTool("delete_event", args));

server.tool("list_emails", "List emails from inbox.",
  { unread_only: z.boolean().optional(), from: z.string().optional(), date: z.string().optional(), max_count: z.number().optional() },
  async (args) => callTool("list_emails", args));

server.tool("read_email", "Read the full content of an email. Use get_attachments for files.",
  { item_id: z.string() },
  async (args) => callTool("read_email", args));

server.tool("send_email", "Send an email. The first call returns a preview and sends nothing; after the user approves, call again with exactly the same arguments to send.",
  { to: z.array(z.string()), cc: z.array(z.string()).optional(), bcc: z.array(z.string()).optional(), subject: z.string(), body: z.string(), direction: z.enum(["auto","rtl","ltr"]).optional().describe("auto=detect, rtl=Persian/Arabic, ltr=English") },
  async (args) => callTool("send_email", args));

server.tool("reply_email", "Reply to an existing email. The first call returns a preview and sends nothing; after the user approves, call again with exactly the same arguments to send.",
  { item_id: z.string(), body: z.string(), reply_all: z.boolean().optional(), direction: z.enum(["auto","rtl","ltr"]).optional().describe("auto=detect, rtl=Persian/Arabic, ltr=English") },
  async (args) => callTool("reply_email", args));

server.tool("get_attachments", "ALWAYS use this tool when user asks to download/open/view an attachment. Returns browser download URLs.",
  { item_id: z.string() },
  async (args) => callTool("get_attachments", args));

const transport = new StdioServerTransport();
await server.connect(transport);
