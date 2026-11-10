# Microsoft Exchange 2019 On-Premises Claude MCP

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
git clone https://github.com/shahmirdelfanazari/Microsoft-Exchange-2019-ON-Premises-Claude-MCP.git
cd Microsoft-Exchange-2019-ON-Premises-Claude-MCP
npm install
cp .env.example .env              # fill in your values
cp rooms.example.json rooms.json  # list your room mailboxes
# optional: copy your AD CA certificate to ./ldaps-ca.pem
npm start
```

### Exchange

The server only impersonates user mailboxes (the signed-in user) and room mailboxes (to confirm bookings), so give the service account impersonation over those only. Shared, discovery, system and equipment mailboxes stay out of reach:

```powershell
New-ManagementScope -Name "exchange-mcp-scope" -RecipientRestrictionFilter `
  "(RecipientTypeDetails -eq 'UserMailbox') -or (RecipientTypeDetails -eq 'RoomMailbox')"
# Preview who is in scope:
Get-Recipient -RecipientPreviewFilter (Get-ManagementScope "exchange-mcp-scope").RecipientFilter -ResultSize Unlimited |
  Group-Object RecipientTypeDetails
New-ManagementRoleAssignment -Name "exchange-mcp-impersonation" `
  -Role ApplicationImpersonation -User svc-exchange-mcp -CustomRecipientWriteScope "exchange-mcp-scope"
```

The same account is used for the LDAP bind by default. To keep the two apart, create a second account with no Exchange rights (any domain user can read the directory) and set `LDAP_BIND_UPN` and `LDAP_BIND_PASSWORD`.

Room mailboxes should be **auto-accept** resource mailboxes.

### OIDC client (Keycloak)

- Client ID `exchange-mcp` (or whatever you set in `OIDC_CLIENT_ID`), standard flow, PKCE S256.
- Redirect URIs: `http://localhost*` (Claude Code) and `https://<PUBLIC_URL>/auth/oauth-callback`.
- Optional, stricter: add an **audience mapper** to the client that puts your `PUBLIC_URL` into the access token's `aud`, and set `OIDC_AUDIENCE` to the same value. The server then only accepts tokens issued for it specifically.
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

Replace `https://mcp.example.com` with your `PUBLIC_URL`. Each user signs in once with your OIDC provider in the browser; nobody types a password into Claude.

> **Internal server or public server?** Claude Code and the Claude Desktop setup below connect **from the user's computer**, so they work with a server on your internal network or VPN. Custom connectors added in claude.ai or in Claude Desktop's *Connectors* settings connect **from Anthropic's cloud**, so they need a server reachable from the internet.

### Claude Code

```bash
claude mcp add exchange --transport http https://mcp.example.com/mcp
```

Claude Code opens the sign-in page on first use (or run `/mcp` and choose **Authenticate**).

### Claude Desktop on macOS or Windows: desktop extension (recommended)

The `desktop-extension/` folder is a Claude Desktop extension (`.mcpb`). It runs on the user's computer, so it works with a server on your internal network or VPN, and Claude Desktop runs it with its built-in Node.js, so users install nothing else. It holds **no secrets**: at first use it reads the sign-in settings from your server, so the only setting is the server URL.

**How sign-in works:** on the first tool call the extension opens the browser at your OIDC provider. After sign-in the provider redirects to `<PUBLIC_URL>/auth/oauth-callback`, and the extension collects the tokens from `<PUBLIC_URL>/auth/poll-token` with its PKCE verifier. Tokens are refreshed automatically and stored only on the user's computer (`%APPDATA%.claudeexchange-mcp-token.json` on Windows, `~/.claude/exchange-mcp-token.json` on macOS).

#### Build the `.mcpb` (IT admin, once)

You need Node.js 20+ and the repository.

1. Make sure your OIDC client allows the redirect URI `https://<PUBLIC_URL>/auth/oauth-callback` (see [OIDC client](#oidc-client-keycloak)).
2. Optional but recommended: pre-configure the extension so users only click **Install**, with no settings to type. In `desktop-extension/manifest.json` replace the two `${user_config...}` values under `server.mcp_config.env` with your values, e.g. `"EXCHANGE_MCP_URL": "https://mcp.example.com"` and `"UI_LANGUAGE": "fa"` (or `en`), and delete the whole `user_config` block. (Pre-filled `default` values in `user_config` are not reliably applied by Claude Desktop, so don't rely on them.) You can also change `display_name`.
3. Build:

   ```bash
   cd desktop-extension
   npm install --omit=dev
   npx @anthropic-ai/mcpb@2.1.2 pack . exchange-2019.mcpb
   ```

   This writes `exchange-2019.mcpb` (the manifest, `proxy.js`, `messages.js` and their `node_modules`). When you change anything, raise `version` in `manifest.json` and build again.
4. Share the file with your users through an internal channel (intranet or file share).

#### Install (each user)

1. Open **Claude Desktop** (macOS or Windows) and sign in.
2. Double-click `exchange-2019.mcpb`, or drag it into the Claude Desktop window. Or install it from the settings:
   - newer versions: **Settings → Desktop app → Extensions: Manage → Advanced settings → Install Extension…**
   - older versions: **Settings → Extensions → Advanced settings → Install Extension…**
3. Review the details and click **Install**. Claude Desktop may warn that the developer is not verified by Anthropic; that is normal for an extension your IT team built. If the server URL wasn't pre-filled, enter the one your IT team gave you (e.g. `https://mcp.example.com`), then make sure the extension is **enabled**.
4. Start a new chat and ask, for example, *"What meetings do I have tomorrow?"*. A browser window opens with your organization's sign-in page; sign in, then return to Claude. The first answer may say the browser opened; just ask again.

To sign out or switch users, ask Claude to **log out** (the `logout` tool). To update, install the new `.mcpb` the same way. To remove, uninstall it in the Extensions settings.

### claude.ai or Claude Desktop custom connector (internet-facing server only)

**Settings → Connectors → Add custom connector**, name it `Exchange` and use `https://mcp.example.com/mcp`, then **Connect** and sign in. On Team and Enterprise plans an owner adds the connector under organization settings first. Read [SECURITY.md](SECURITY.md) before exposing the server: the service account can read every mailbox.

### Troubleshooting

| Symptom | Fix |
|---|---|
| Extension installed but no Exchange tools in chat | Check it is enabled under **Settings → Desktop app → Extensions** (older versions: **Settings → Extensions**), then start a new chat. Logs: **Settings → Developer → Open Logs Folder**. |
| "The extension has no server URL" | open this extension in the Extensions settings → **Configure**, enter your `PUBLIC_URL`. |
| "Could not reach the server's sign-in settings" | Wrong server URL, or the computer is off the internal network/VPN. Open `<PUBLIC_URL>/health` in the browser to check. |
| Browser opens but sign-in page says invalid redirect URI | Add `https://<PUBLIC_URL>/auth/oauth-callback` (extension) and `http://localhost*` (Claude Code) to the OIDC client's redirect URIs. |
| `Issuer mismatch in authorization response` (Claude Code) | Turn on Keycloak's *Exclude Issuer From Authentication Response* (see [OIDC client](#oidc-client-keycloak)). |
| Signed in as the wrong person, or sign-in loops | Ask Claude to log out, or delete `exchange-mcp-token.json` (path above) and try again. |
| Custom connector can't connect | The server isn't reachable from the internet. Use the desktop extension instead. |

## Customizing

- **Timezone:** Iran time (fixed +210 minutes, no DST) is used in `nowIran()`, `isPastDateTime()`, `iranLocalToMs()`, `get_current_time` and the availability request (`Bias=-210`). Change these for another zone.
- **Work week and hours:** `WORK_DAYS` (Saturday to Wednesday; used when suggesting other days), `OPEN_DAYS` (adds Thursday: bookable when asked for, never suggested; Friday is closed), `WORK_START_HOUR` and `WORK_END_HOUR` in `index.js`.
- **Language:** every user-facing string lives in `locales/en.js` and `locales/fa.js`. `UI_LANGUAGE` chooses which one is used. To add a language, copy `locales/en.js` (keep every key), translate it, and register it in `i18n.js`.

## Security

Read [SECURITY.md](SECURITY.md) before deploying. In short: the service account can read every mailbox, so keep the server on your internal network and keep `.env` readable by root only.

## License

[MIT](LICENSE)

Independent open-source project, not affiliated with or endorsed by Microsoft or Anthropic. Exchange and Active Directory are trademarks of Microsoft Corporation; Claude is a trademark of Anthropic.
