# Microsoft Exchange 2019 On-Premises MCP

An [MCP](https://modelcontextprotocol.io) server that connects Claude (claude.ai, Claude Desktop, Claude Code) to **on-premises Microsoft Exchange** (via EWS) and **Active Directory**. Users can book meeting rooms, check colleagues' free/busy, manage calendar events and handle email in natural language.

Users sign in with your **OpenID Connect provider** (tested with Keycloak). The server validates their JWT and acts as them in Exchange through one service account with **ApplicationImpersonation**, so no user password ever reaches the server.

> **Language:** replies are in **English** by default; set `UI_LANGUAGE=fa` for **Persian (Farsi)**. Times are handled in **Iran Standard Time (UTC+03:30)**, which is easy to change: see [Customizing](#customizing).

## Features

- **Safe booking.** Every booking is two steps: a preview, then `confirmed=true`. The schema requires it. Free/busy is checked for the organizer, attendees and room, and checked again on confirm. Dates are resolved server-side, so a stale date from the model is visible to the user before anything is sent. Past dates are rejected.
- **Room verification with rollback.** After booking, the server polls the room's own calendar until it holds a meeting with the same `calendar:UID`. If the room declined (a race or a booking policy), the meeting is deleted by `ItemId`.
- **Recurring meetings:** daily, weekly and monthly series. Availability is checked for every occurrence, and one conflict refuses the whole series.
- **Room access control:** restrict a room to members of an AD group. Nested groups are checked with `LDAP_MATCHING_RULE_IN_CHAIN`, and the check fails closed.
- **Org-chart aware:** book a meeting with your team or your direct reports, and look up managers through LDAP.
- **Email:** list, read, send and reply, plus attachment download links.
- **Persian-aware user search:** normalizes Arabic/Persian letter variants.

### Tools

| Area | Tools |
|---|---|
| Calendar | `smart_schedule`, `check_availability`, `list_events`, `update_event`, `delete_event`, `list_rooms`, `get_current_time` |
| Team / group | `book_meeting_with_team`, `book_meeting_with_direct_reports`, `book_for_group` |
| Directory | `search_user`, `get_manager`, `get_direct_reports`, `resolve_team`, `resolve_group` |
| Email | `list_emails`, `read_email`, `send_email`, `reply_email`, `send_email_to_team`, `get_attachments` |
| Session | `logout` |

## Architecture

```
Claude (connector / Claude Code)  ── Authorization: Bearer <OIDC JWT> ──►  reverse proxy (TLS)
                                                                             ├─ /       → 127.0.0.1:3000  index.js (MCP, Streamable HTTP)
                                                                             └─ /auth/  → 127.0.0.1:3001  login-server.js
index.js ── EWS SOAP / NTLM / ExchangeImpersonation ──► Exchange (EWS)
index.js ── LDAPS ─────────────────────────────────────► Active Directory
index.js ── JWKS verify ───────────────────────────────► OIDC provider
```

The server publishes `/.well-known/oauth-protected-resource` and `/.well-known/oauth-authorization-server`, so MCP clients discover the OAuth login automatically.

## Requirements

- Node.js 20+
- Exchange 2016/2019 with EWS enabled
- A service account with the **ApplicationImpersonation** role, which is also used to bind to LDAP
- An OIDC provider. Users' tokens must carry an `email` claim that matches their Exchange primary SMTP address.
- A reverse proxy with TLS, such as nginx (see `deploy/nginx.conf.example`)

## Setup

```bash
git clone https://github.com/shahmirdelfanazari/Microsoft-Exchange-2019-ON-Premises-MCP.git
cd Microsoft-Exchange-2019-ON-Premises-MCP
npm install
cp .env.example .env              # fill in your values
cp rooms.example.json rooms.json  # list your room mailboxes
# optional: copy your AD CA certificate to ./ldaps-ca.pem
npm start
```

### Exchange

```powershell
New-ManagementRoleAssignment -Name "mail-mcp-impersonation" `
  -Role ApplicationImpersonation -User svc-mail-mcp
```

Room mailboxes should be **auto-accept** resource mailboxes.

### OIDC client (Keycloak)

- Client ID `mail-mcp` (or whatever you set in `OIDC_CLIENT_ID`), standard flow, PKCE S256.
- Redirect URIs: `http://localhost*` (Claude Code) and `https://<PUBLIC_URL>/auth/oauth-callback`.
- Turn **Advanced → OpenID Connect Compatibility Modes → "Exclude Issuer From Authentication Response"** ON. MCP clients enforce RFC 9207, and this server advertises itself as the issuer. Without this setting, login fails with `Issuer mismatch in authorization response`.

### Rooms (`rooms.json`)

```json
{
  "rooms":      [{ "email": "room-a1@example.com", "name": "A1 (6-8 people)" }],
  "restricted": { "room-exec@example.com": "exec-room@example.com" },
  "excluded":   ["room-other-building@example.com"],
  "sizeGuide":  "2 people→A2, 3-4→B1, 6-8→A1"
}
```

- `rooms` is the fallback list, used when Exchange has no room lists. It also supplies display names.
- `restricted` maps a room to an AD group (by `mail` or `sAMAccountName`); only members can book it. If the group is missing, nobody can book the room.
- `excluded` lists rooms that are never bookable.
- `sizeGuide` is shown to the model.

### Running in production

Use pm2 with `deploy/ecosystem.config.cjs.example`, and run a single process (MCP sessions live in memory). Bind the server to localhost only and expose it through the reverse proxy.

## Connecting Claude

- **Claude Code:** `claude mcp add exchange --transport http https://mail-mcp.example.com/mcp`
- **claude.ai / Claude Desktop:** add a custom connector pointing at `https://mail-mcp.example.com/mcp`.

## Customizing

- **Timezone:** Iran time (fixed +210 minutes, no DST) is used in `nowIran()`, `isPastDateTime()`, `iranLocalToMs()`, `get_current_time` and the availability request (`Bias=-210`). Change these for another zone.
- **Work week and hours:** `isWorkDay()` (Friday off), `WORK_START_HOUR` and `WORK_END_HOUR` in `index.js`.
- **Language:** every user-facing string lives in `locales/en.js` and `locales/fa.js`. `UI_LANGUAGE` chooses which one is used. To add a language, copy `locales/en.js` (keep every key), translate it, and register it in `i18n.js`.

## Security

Read [SECURITY.md](SECURITY.md) before deploying. In short: the service account can read every mailbox, so keep the server on your internal network and keep `.env` readable by root only.

## License

[MIT](LICENSE)
