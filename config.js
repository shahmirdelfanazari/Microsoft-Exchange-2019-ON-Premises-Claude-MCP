// ─── Deployment configuration ────────────────────────────────────────────────
// Every organization-specific value comes from the environment (see .env.example)
// or from the rooms file (see rooms.example.json). Nothing secret lives in code.
import { readFileSync, existsSync } from "fs";

function required(name) {
  const v = process.env[name];
  if (!v) {
    console.error(`❌ Missing required environment variable ${name} — see .env.example`);
    process.exit(1);
  }
  return v;
}
const optional = (name, def) => process.env[name] || def;

// Mail domain of your organization, e.g. "example.com"
export const MAIL_DOMAIN = required("MAIL_DOMAIN").toLowerCase();

// Exchange Web Services endpoint, e.g. https://mail.example.com/EWS/Exchange.asmx
export const EWS_URL = required("EWS_URL");
// The EWS certificate is verified against Node's CA store, plus this CA (PEM) if the file exists.
// EWS_TLS_INSECURE=true turns verification off (not recommended: exposes the service account).
const ewsCaPath = optional("EWS_CA_PATH", "");
export const EWS_CA = ewsCaPath && existsSync(ewsCaPath) ? readFileSync(ewsCaPath, "utf8") : undefined;
export const EWS_TLS_INSECURE = optional("EWS_TLS_INSECURE", "false").toLowerCase() === "true";

// Service account with the ApplicationImpersonation role (also used for the LDAP bind)
export const SVC_USERNAME = required("SVC_USERNAME");
export const SVC_PASSWORD = required("SVC_PASSWORD");
export const SVC_UPN = optional("SVC_UPN", `${SVC_USERNAME}@${MAIL_DOMAIN}`);
// Optional separate, read-only account for the LDAP bind, so a leaked LDAP credential
// cannot impersonate mailboxes. Defaults to the service account above.
export const LDAP_BIND_UPN = optional("LDAP_BIND_UPN", SVC_UPN);
export const LDAP_BIND_PASSWORD = optional("LDAP_BIND_PASSWORD", SVC_PASSWORD);

// OpenID Connect provider (tested with Keycloak), e.g. https://sso.example.com/realms/Main
export const OIDC_ISSUER = required("OIDC_ISSUER").replace(/\/$/, "");
export const OIDC_AUTH_BASE = optional("OIDC_AUTH_BASE", `${OIDC_ISSUER}/protocol/openid-connect`);
export const OIDC_JWKS_URL = optional("OIDC_JWKS_URL", `${OIDC_AUTH_BASE}/certs`);
export const OIDC_CLIENT_ID = optional("OIDC_CLIENT_ID", "exchange-mcp");
// Optional: only for confidential clients. Leave empty for a public PKCE client.
// (KEYCLOAK_CLIENT_SECRET is accepted as a legacy name.)
export const OIDC_CLIENT_SECRET = optional("OIDC_CLIENT_SECRET", optional("KEYCLOAK_CLIENT_SECRET", ""));
// Access tokens are accepted only when issued to one of these clients (azp or aud).
// Comma-separated; defaults to OIDC_CLIENT_ID. Tokens other apps in the realm obtained are rejected.
export const OIDC_ALLOWED_CLIENTS = optional("OIDC_ALLOWED_CLIENTS", OIDC_CLIENT_ID).split(",").map(s => s.trim()).filter(Boolean);
// Reject tokens whose email claim is not verified (set false only if your provider never sets email_verified).
export const OIDC_REQUIRE_EMAIL_VERIFIED = optional("OIDC_REQUIRE_EMAIL_VERIFIED", "true").toLowerCase() !== "false";
// Optional: also require this value in the token's aud claim (e.g. your PUBLIC_URL). Needs an
// audience mapper on the client at your provider, so tokens are issued for this server specifically.
export const OIDC_AUDIENCE = optional("OIDC_AUDIENCE", "");
// Desktop extensions before 2.1 sent the token as a session_token tool argument instead of the
// Authorization header. Set true only while such extensions are still installed.
export const LEGACY_TOKEN_ARG = optional("LEGACY_TOKEN_ARG", "false").toLowerCase() === "true";

// Each MCP session holds about 1.5 MB. New sessions are refused above MAX_SESSIONS; a user who
// opens more than MAX_SESSIONS_PER_USER loses their least recently used one.
export const MAX_SESSIONS = Number(optional("MAX_SESSIONS", "150"));
export const MAX_SESSIONS_PER_USER = Number(optional("MAX_SESSIONS_PER_USER", "8"));

// Public HTTPS URL of this server (behind your reverse proxy), e.g. https://mcp.example.com
export const PUBLIC_URL = required("PUBLIC_URL").replace(/\/$/, "");

// Language of replies shown to users: "en" or "fa" (strings live in locales/)
export const UI_LANGUAGE = optional("UI_LANGUAGE", "en").toLowerCase();

export const PORT = Number(optional("PORT", "3000"));
export const LOGIN_PORT = Number(optional("LOGIN_PORT", "3001"));

// Active Directory over LDAPS — comma-separated list, tried in order
export const LDAP_URLS = required("LDAP_URLS").split(",").map(s => s.trim()).filter(Boolean);
export const LDAP_BASE_DN = required("LDAP_BASE_DN");
// CA certificate that signed your domain controllers' certificates (PEM).
// If the file does not exist, Node's default CA store is used.
const caPath = optional("LDAPS_CA_PATH", "./ldaps-ca.pem");
export const LDAPS_CA = existsSync(caPath) ? readFileSync(caPath) : undefined;

// ─── Rooms ───────────────────────────────────────────────────────────────────
// rooms.json: { rooms: [{email, name}], restricted: {roomEmail: groupEmail},
//               excluded: [roomEmail], sizeGuide: "text for the model" }
const roomsPath = optional("ROOMS_FILE", "./rooms.json");
let roomsCfg = { rooms: [], restricted: {}, excluded: [], sizeGuide: "" };
if (existsSync(roomsPath)) {
  roomsCfg = { ...roomsCfg, ...JSON.parse(readFileSync(roomsPath, "utf8")) };
} else {
  console.warn(`⚠️  ${roomsPath} not found — room list will come only from Exchange room lists.`);
}
const lc = s => String(s).toLowerCase();

export const ROOMS = roomsCfg.rooms.map(r => ({ email: lc(r.email), name: r.name || r.email }));
export const RESTRICTED_ROOMS = Object.fromEntries(
  Object.entries(roomsCfg.restricted).map(([room, group]) => [lc(room), lc(group)])
);
export const EXCLUDED_ROOMS = roomsCfg.excluded.map(lc);
export const ROOM_SIZE_GUIDE = roomsCfg.sizeGuide || "Pick a room whose capacity (shown in its name) fits the number of attendees.";
