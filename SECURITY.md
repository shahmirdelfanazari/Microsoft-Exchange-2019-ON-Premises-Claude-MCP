# Security

## Deployment model

- The service account has **ApplicationImpersonation**: whoever holds its password can read and send mail as anyone. Use a strong password, monitor lockouts, and store it only in `.env` (mode 600).
- Run the server on an **internal network**. Both Node processes bind to `127.0.0.1`; expose them only through a TLS reverse proxy.
- With a confidential OIDC client, `POST /oauth/register` hands the client secret to any caller, which is how MCP clients obtain it. The secret therefore only protects against callers who cannot reach the server. Prefer a public PKCE client if your provider allows it.
- Every request is authorized by a JWT verified against the provider's JWKS (`issuer` checked). The user's identity is the `email` claim.

## Known limitations

- TLS to Exchange is not verified (`rejectUnauthorized: false` in `ewsRequest`). Pin your internal CA if you can.
- Some user values are interpolated into SOAP bodies and LDAP filters without escaping (e.g. `update_event` subject, `send_email` subject, LDAP `mail=` filters).
- `send_email` sends immediately; it has no server-side confirmation gate.
- Attachments are written to `/tmp` and deleted after 10 minutes. Files left behind by a restart are not cleaned up.

## Reporting a vulnerability

Please open a private security advisory on GitHub rather than a public issue.
