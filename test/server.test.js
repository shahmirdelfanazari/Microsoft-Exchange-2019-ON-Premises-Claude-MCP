// Starts the real server against a fake OIDC provider (local JWKS). Exchange and LDAP point at a closed
// port, so only what needs neither is exercised: authentication, sessions, limits and the email preview.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import path from "node:path";
import * as jose from "jose";

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const freePort = () => new Promise(r => { const s = createServer(); s.listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => r(p)); }); });

let jwksServer, child, BASE, ISSUER, key, otherKey;
const CLIENT = "exchange-mcp";

function baseEnv(port, loginPort) {
  return {
    ...process.env,
    MAIL_DOMAIN: "example.com", EWS_URL: "https://127.0.0.1:9/EWS/Exchange.asmx",
    SVC_USERNAME: "svc-exchange-mcp", SVC_PASSWORD: "not-a-real-password",
    OIDC_ISSUER: ISSUER, OIDC_JWKS_URL: `${ISSUER}/certs`, OIDC_CLIENT_ID: CLIENT,
    PUBLIC_URL: "https://mcp.example.com", PORT: String(port), LOGIN_PORT: String(loginPort),
    LDAP_URLS: "ldaps://127.0.0.1:9", LDAP_BASE_DN: "DC=example,DC=com",
    ROOMS_FILE: path.join(ROOT, "rooms.example.json"), MAX_SESSIONS_PER_USER: "2", UI_LANGUAGE: "en",
  };
}
const token = (claims = {}, { signKey = key, expiresIn = "5m", issuer = ISSUER } = {}) =>
  new jose.SignJWT({ azp: CLIENT, typ: "Bearer", email: "ali@example.com", email_verified: true, ...claims })
    .setProtectedHeader({ alg: "RS256", kid: "test" }).setIssuer(issuer).setIssuedAt().setExpirationTime(expiresIn).sign(signKey);

let id = 1;
async function rpc(method, params, { bearer, sid } = {}) {
  const headers = { "content-type": "application/json", accept: "application/json, text/event-stream" };
  if (bearer) headers.authorization = `Bearer ${bearer}`;
  if (sid) headers["mcp-session-id"] = sid;
  const res = await fetch(`${BASE}/mcp`, { method: "POST", headers, body: JSON.stringify({ jsonrpc: "2.0", id: id++, method, params }) });
  const line = (await res.text()).split("\n").find(l => l.startsWith("{") || l.startsWith("data: ")) || "{}";
  let body = {}; try { body = JSON.parse(line.replace(/^data: /, "")); } catch {}
  return { status: res.status, sid: res.headers.get("mcp-session-id"), www: res.headers.get("www-authenticate"), body, text: body?.result?.content?.[0]?.text || "" };
}
const INIT = { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "1" } };
async function open(bearer) {
  const r = await rpc("initialize", INIT, { bearer });
  if (r.sid) await rpc("notifications/initialized", {}, { bearer, sid: r.sid });
  return r;
}
const call = (name, args, opts) => rpc("tools/call", { name, arguments: args }, opts);

before(async () => {
  const pair = await jose.generateKeyPair("RS256");
  key = pair.privateKey;
  otherKey = (await jose.generateKeyPair("RS256")).privateKey;
  const jwk = { ...(await jose.exportJWK(pair.publicKey)), kid: "test", alg: "RS256", use: "sig" };
  jwksServer = createServer((req, res) => { res.setHeader("content-type", "application/json"); res.end(JSON.stringify({ keys: [jwk] })); });
  await new Promise(r => jwksServer.listen(0, "127.0.0.1", r));
  ISSUER = `http://127.0.0.1:${jwksServer.address().port}/realms/test`;
  const port = await freePort(), loginPort = await freePort();
  BASE = `http://127.0.0.1:${port}`;
  child = spawn(process.execPath, ["index.js"], { cwd: ROOT, env: baseEnv(port, loginPort), stdio: "ignore" });
  for (let i = 0; i < 50; i++) {
    try { if ((await fetch(`${BASE}/health`)).ok) return; } catch {}
    await new Promise(r => setTimeout(r, 200));
  }
  throw new Error("server did not start");
});
after(() => { child?.kill(); jwksServer?.close(); });

test("requests without a valid token get 401 and create no session", async () => {
  const r = await rpc("initialize", INIT);
  assert.equal(r.status, 401);
  assert.match(r.www, /resource_metadata=/);
  assert.equal(r.sid, null);
  assert.equal((await (await fetch(`${BASE}/health`)).json()).mcpSessions, 0);
});

test("tokens that are not for this app are refused", async () => {
  const refused = async (t, why) => assert.equal((await rpc("initialize", INIT, { bearer: await t })).status, 401, why);
  await refused(token({ azp: "another-app" }), "issued to another client");
  await refused(token({ typ: "ID" }), "ID token");
  await refused(token({ email_verified: false }), "unverified email");
  await refused(token({ email: undefined }), "no email");
  await refused(token({}, { expiresIn: "-1m" }), "expired");
  await refused(token({}, { issuer: "http://127.0.0.1/realms/other" }), "wrong issuer");
  await refused(token({}, { signKey: otherKey }), "signed with another key");
  await refused("eyJhbGciOiJSUzI1NiJ9.e30.x", "garbage");
  // aud naming this client is accepted even when azp differs
  assert.equal((await rpc("initialize", INIT, { bearer: await token({ azp: "gateway", aud: ["account", CLIENT] }) })).status, 200);
});

test("a signed-in user gets a session and the tools", async () => {
  const bearer = await token({ email: "tools@example.com" });
  const s = await open(bearer);
  assert.equal(s.status, 200);
  assert.ok(s.sid);
  const tools = (await rpc("tools/list", {}, { bearer, sid: s.sid })).body.result.tools;
  assert.equal(tools.length, 22);
  assert.ok(!JSON.stringify(tools).includes("session_token"));
  assert.match((await call("get_current_time", {}, { bearer, sid: s.sid })).text, /Timezone/);
});

test("a session id never replaces the token, and belongs to its user", async () => {
  const bearer = await token({ email: "owner@example.com" });
  const s = await open(bearer);
  assert.equal((await call("get_current_time", {}, { sid: s.sid })).status, 401, "no token");
  assert.equal((await call("get_current_time", { session_token: bearer }, { sid: s.sid })).status, 401, "token as an argument");
  assert.equal((await call("get_current_time", {}, { bearer: await token({ email: "intruder@example.com" }), sid: s.sid })).status, 404, "another user's token");
  assert.equal((await call("get_current_time", {}, { bearer, sid: "00000000-0000-4000-8000-000000000000" })).status, 404, "unknown session");
  assert.equal((await call("get_current_time", {}, { bearer, sid: s.sid })).status, 200);
});

test("sessions per user are capped: the oldest is closed", async () => {
  const bearer = await token({ email: "many@example.com" });
  const first = await open(bearer);
  await open(bearer); await open(bearer);   // MAX_SESSIONS_PER_USER=2
  assert.equal((await call("get_current_time", {}, { bearer, sid: first.sid })).status, 404);
});

test("send_email previews first and only sends an identical repeat", async () => {
  const bearer = await token({ email: "mail@example.com" });
  const { sid } = await open(bearer);
  const mail = { to: ["sara@example.com"], subject: "Hello", body: "First line" };
  const preview = await call("send_email", mail, { bearer, sid });
  assert.match(preview.text, /nothing has been sent/);
  assert.match(preview.text, /sara@example\.com/);
  assert.match((await call("send_email", mail, { bearer, sid })).text, /nothing has been sent/, "a duplicate fired right away is still a preview");
  assert.match((await call("send_email", { ...mail, to: ["sara@example.com", "eve@example.com"] }, { bearer, sid })).text, /nothing has been sent/, "changed recipients are a new preview");
  await new Promise(r => setTimeout(r, 2100));
  // The identical repeat goes on to Exchange, which is unreachable here: the tool must report the failure.
  const sent = await call("send_email", mail, { bearer, sid });
  assert.doesNotMatch(sent.text, /nothing has been sent|Email sent/);
  assert.match(sent.text, /^❌/);
  assert.match((await call("send_email", mail, { bearer, sid })).text, /nothing has been sent/, "the confirmation was used up");
});

test("anonymous requests are rate limited; signed-in users are not caught by it", async () => {
  let limited = false;
  for (let i = 0; i < 130 && !limited; i++) limited = (await rpc("initialize", INIT)).status === 429;
  assert.ok(limited);
  assert.equal((await fetch(`${BASE}/oauth/register`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" })).status, 429);
  assert.equal((await open(await token({ email: "calm@example.com" }))).status, 200);
});

test("the server refuses to start with plain http:// or ldap:// addresses", async () => {
  const run = extra => new Promise(async resolve => {
    const p = spawn(process.execPath, ["index.js"], { cwd: ROOT, env: { ...baseEnv(await freePort(), await freePort()), ...extra }, stdio: ["ignore", "ignore", "pipe"] });
    let err = ""; p.stderr.on("data", d => err += d);
    const timer = setTimeout(() => { p.kill(); resolve({ code: "still running", err }); }, 5000);
    p.on("exit", code => { clearTimeout(timer); resolve({ code, err }); });
  });
  const http = await run({ EWS_URL: "http://127.0.0.1:9/EWS/Exchange.asmx" });
  assert.equal(http.code, 1); assert.match(http.err, /EWS_URL must start with https:\/\//);
  const ldap = await run({ LDAP_URLS: "ldap://127.0.0.1:9" });
  assert.equal(ldap.code, 1); assert.match(ldap.err, /LDAP_URLS must start with ldaps:\/\//);
});
