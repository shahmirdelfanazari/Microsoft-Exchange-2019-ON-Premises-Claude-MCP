# Security

## Deployment model

- The service account has **ApplicationImpersonation**: whoever holds its password can read and send mail as anyone. Use a strong password, monitor lockouts, and store it only in `.env` (mode 600).
- Run the server on an **internal network**. Both Node processes bind to `127.0.0.1`; expose them only through a TLS reverse proxy.
- With a confidential OIDC client, `POST /oauth/register` hands the client secret to any caller, which is how MCP clients obtain it. The secret therefore only protects against callers who cannot reach the server. Prefer a public PKCE client if your provider allows it.
- Every request is authorized by a JWT verified against the provider's JWKS (`issuer` checked). The user's identity is the `email` claim.

## Desktop extension

- The `.mcpb` contains no secrets and no organization data. It reads the OIDC endpoints and client id from your server at first use, so anyone who has the file still needs network access to the server and a valid user sign-in.
- The server URL must use `https://` (plain `http://` is accepted only for `localhost`). The sign-in URL from the server must be an http(s) URL without quote characters before it is opened in the browser.
- Access and refresh tokens are stored in the user's profile (`%APPDATA%\.claude\exchange-mcp-token.json` or `~/.claude/exchange-mcp-token.json`, mode 600 where supported), not in the OS keychain. Anyone with access to that user account can use them until they expire; `logout` deletes the file and ends the provider session.
- Distribute the file through an internal channel, and raise `version` in `manifest.json` for every rebuild so users can tell builds apart.

## Known limitations

- TLS to Exchange is not verified (`rejectUnauthorized: false` in `ewsRequest`). Pin your internal CA if you can.
- Some user values are interpolated into SOAP bodies and LDAP filters without escaping (e.g. `update_event` subject, `send_email` subject, LDAP `mail=` filters).
- `send_email` sends immediately; it has no server-side confirmation gate.
- Attachments are written to `/tmp` and deleted after 10 minutes. Files left behind by a restart are not cleaned up.

## Reporting a vulnerability

Please open a private security advisory on GitHub rather than a public issue.
