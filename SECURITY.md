# Security

## Deployment model

- The service account has **ApplicationImpersonation**: whoever holds its password can read and send mail as anyone. Use a strong password, monitor lockouts, and store it only in `.env` (mode 600).
- Run the server on an **internal network**. Both Node processes bind to `127.0.0.1`; expose them only through a TLS reverse proxy.
- With a confidential OIDC client, `POST /oauth/register` hands the client secret to any caller, which is how MCP clients obtain it. The secret therefore only protects against callers who cannot reach the server. Prefer a public PKCE client if your provider allows it.
- Every HTTP request to `/mcp` must carry the user's access token in `Authorization: Bearer`. It is checked before anything else: no session is created without a valid token, a session id never replaces the token, and a session can only be used by the user who opened it. (`LEGACY_TOKEN_ARG=true` relaxes this for desktop extensions older than 2.1, which sent the token as a tool argument; leave it off.)
- Sessions are capped (`MAX_SESSIONS`, `MAX_SESSIONS_PER_USER`) and requests are rate limited in memory: per client IP without a valid token (also `/oauth/register`), per user with one.
- The JWT is verified against the provider's JWKS. The token must come from `OIDC_ISSUER`, be an access token issued to this app (`azp` or `aud` in `OIDC_ALLOWED_CLIENTS`, default `OIDC_CLIENT_ID`), and carry a verified `email` (`email_verified=true`, see `OIDC_REQUIRE_EMAIL_VERIFIED`). Tokens other apps in the same realm obtained, ID tokens and unverified emails are rejected. The token must also name this server in `aud` (`OIDC_AUDIENCE`, set by an audience mapper at the provider); `OIDC_AUDIENCE=none` turns that off. `azp` says which client obtained a token and `aud` which service it is for; both are checked. The user's identity is the `email` claim, so users must not be able to change their own email at the provider (e.g. LDAP/AD federation in read-only mode).
- Limit what impersonation can reach with an Exchange management scope: user and room mailboxes only (see the README), optionally minus a group of protected mailboxes. Use `New-ManagementScope` and `Set-ManagementRoleAssignment -CustomRecipientWriteScope`.
- The EWS certificate is verified (Node's CA store, plus `EWS_CA_PATH` for an internal CA). `EWS_TLS_INSECURE=true` disables this; avoid it, since the service account's NTLM login could then be intercepted.
- Values from users and the model are XML-escaped in every SOAP request and RFC 4515-escaped in every LDAP filter.

## OAuth discovery: a deliberate trade-off

The server publishes `/.well-known/oauth-authorization-server` with **itself** as `issuer`, the provider's authorization and token endpoints, and a static `/oauth/register` that hands every client the one pre-configured client. This lets MCP clients that rely on dynamic client registration (Claude Code, claude.ai connectors) connect without the provider allowing anonymous registration. The cost:

- The issuer in the metadata is not the issuer of the tokens (your provider). Clients that check the `iss` parameter of the authorization response (RFC 9207) see a mismatch, which is why Keycloak's *Exclude Issuer From Authentication Response* must be on, and that removes one defence against authorization-server mix-up.
- Tokens are still verified against the provider's keys, issuer, client and audience, so a token from anywhere else is refused.

The standard alternative is to list the provider's own issuer in `authorization_servers` and give each client its client id (or allow client registration at the provider). That is not implemented.

## Desktop extension

- The `.mcpb` contains no secrets and no organization data. It reads the OIDC endpoints and client id from your server at first use, so anyone who has the file still needs network access to the server and a valid user sign-in.
- Sign-in requests carry the resource indicator (`resource=<server URL>`, RFC 8707). Providers that ignore it (Keycloak relies on the audience mapper instead) are unaffected.
- The server URL must use `https://` (plain `http://` is accepted only for `localhost`). The sign-in URL from the server must be an http(s) URL without quote characters before it is opened in the browser.
- Access and refresh tokens are stored in the user's profile (`%APPDATA%\.claude\exchange-mcp-token.json` or `~/.claude/exchange-mcp-token.json`, mode 600 where supported), not in the OS keychain. Anyone with access to that user account can use them until they expire; `logout` deletes the file and ends the provider session.
- Distribute the file through an internal channel, and raise `version` in `manifest.json` for every rebuild so users can tell builds apart.

## Operating the server

The server holds the one password that can open every mailbox, so treat it as a sensitive host.

- **Keep security updates working.** On Ubuntu, a customized config file (for example a login banner in `/etc/issue`) can make unattended upgrades stop at a prompt and fail every night without anyone noticing. Check `/var/log/unattended-upgrades/` now and then, and let it keep your config files:
  `Dpkg::Options { "--force-confdef"; "--force-confold"; };` in `/etc/apt/apt.conf.d/`.
- **SSH:** keys only (`PasswordAuthentication no`), only from your admin network (firewall), no root login, no TCP forwarding.
- **Rotating the service-account password:** stop the service first (`pm2 stop`), reset the password in AD, update `SVC_PASSWORD` in `.env`, check it (an LDAPS bind and an EWS request), then start the service. A running server would keep retrying the old password and can lock the account. Before restarting, confirm that the value in `.env` is what you set. Keep "password never expires" on and rotate on a schedule instead.
- **Monitor the service account.** It should only ever sign in from this server:
  - Domain controllers: LDAPS binds appear as event 4624 (logon type 3) with this server's IP. Alert on 4624 for the account from any other IP, on failed logons (4625/4776 failures) and on lockouts (4740).
  - EWS logons reach the domain controllers only as event 4776, which has **no client IP**. The client IP is recorded on the Exchange server: in its Security log (4624, type 3) and in the IIS log (`cs-username`, `c-ip`). Watch one of those for the account from any IP other than this server.
  - Impersonated access may be recorded in mailbox audit logs as the mailbox owner's own activity, so don't rely on mailbox-audit reports to spot the service account.
  - Alert on changes to ApplicationImpersonation role assignments and management scopes (Exchange admin audit log).

## Known limitations

- Sending and booking need a preview first. The server remembers each exact request it has previewed (user, tool, all arguments) and acts only on a request that was previewed: once, within 10 minutes, and not within 2 seconds of the preview. `send_email` and `reply_email` are confirmed by repeating the identical call; the booking tools and `send_email_to_team` by `confirmed=true`, which is ignored unless the same request was previewed. A changed recipient, text, time or room is a new preview. The server cannot prove a human approved, so keep tool-call approval on in the client for these tools.
- `update_event` and `delete_event` act on the first call (no preview).
- `logout` closes the MCP session. The server never holds a refresh token, so it cannot end the sign-in at the provider; the client does that (the desktop extension deletes its tokens and calls the provider's logout). Updates use `ConflictResolution="AutoResolve"`: an update made with an out-of-date change key (the event changed after it was read) is refused instead of overwriting the newer version.
- Attachments are written to `/tmp` (mode 600) and deleted after 10 minutes; files a restart left behind are removed at startup.
- `EWS_URL` must be `https://` and `LDAP_URLS` must be `ldaps://`; the server refuses to start otherwise.

## Reporting a vulnerability

Please open a private security advisory on GitHub rather than a public issue.
