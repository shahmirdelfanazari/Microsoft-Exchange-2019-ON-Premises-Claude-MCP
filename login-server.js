// Auxiliary HTTP server (bound to 127.0.0.1:LOGIN_PORT, exposed by the reverse proxy under /auth/).
// - /oauth-callback  receives the OIDC authorization code for desktop-extension style clients
// - /poll-token      lets such a client exchange that code (PKCE) for tokens
// - /dl-file/:id     serves attachments that get_attachments wrote to /tmp (10-minute links)
// - /logged-out      landing page after OIDC logout
import express from "express";
import { readFileSync } from "fs";
import { OIDC_AUTH_BASE, LOGIN_PORT } from "./config.js";

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ── Attachment downloads ──
app.get("/dl-file/:shortId", (req, res) => {
  const id = req.params.shortId;
  if (!/^[0-9a-f-]{36}$/i.test(id)) return res.status(404).send("File not found or expired.");
  const tmpFile = `/tmp/exchange-att-${id}`;
  try {
    const meta = JSON.parse(readFileSync(tmpFile + '.meta', 'utf8'));
    const buffer = readFileSync(tmpFile);
    res.setHeader("Content-Type", meta.contentType || "application/octet-stream");
    res.setHeader("Content-Disposition", `attachment; filename*=UTF-8''${encodeURIComponent(meta.name || "file")}`);
    res.setHeader("Content-Length", buffer.length);
    res.send(buffer);
  } catch (e) {
    res.status(404).send("File not found or expired (links valid for 10 minutes).");
  }
});

// ── OAuth callback from the OIDC provider — stores code for the client to exchange ──
const pendingCodes = new Map(); // state -> {code, created}

app.get("/oauth-callback", (req, res) => {
  const { code, state } = req.query;
  if (code && state) {
    pendingCodes.set(state, { code, created: Date.now() });
    // Clean old entries
    for (const [k, v] of pendingCodes) {
      if (Date.now() - v.created > 300000) pendingCodes.delete(k);
    }
  }
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><style>body{font-family:Vazirmatn,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#1a1a1a;color:#f0c040;direction:rtl}</style></head><body><div style="text-align:center"><h1>✅ ورود موفق</h1><p style="color:#ccd6f6">برگردید به Claude و دوباره امتحان کنید.</p></div></body></html>`);
});

// Client polls this with its state + PKCE verifier to exchange the code for tokens
app.post("/poll-token", async (req, res) => {
  const { state, verifier, client_id, client_secret, redirect_uri } = req.body;
  const pending = pendingCodes.get(state);
  if (!pending) return res.status(404).json({ error: "No pending code for this state" });
  pendingCodes.delete(state);
  try {
    const params = new URLSearchParams({
      client_id, grant_type: "authorization_code", code: pending.code,
      redirect_uri, code_verifier: verifier
    });
    if (client_secret) params.set("client_secret", client_secret);
    const r = await fetch(`${OIDC_AUTH_BASE}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params
    });
    // Always 200 with the provider's JSON body (clients inspect access_token / error)
    res.json(await r.json());
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get("/logged-out", (req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!DOCTYPE html>
<html dir="rtl" lang="fa">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>خروج موفق</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Vazirmatn','Segoe UI',Tahoma,sans-serif; background: #1a1a1a; min-height: 100vh; display: flex; align-items: center; justify-content: center; direction: rtl; }
    .card { background: #242424; border: 1px solid #333; border-radius: 16px; padding: 40px; width: 100%; max-width: 400px; text-align: center; }
    h1 { color: #f0c040; font-size: 24px; margin-bottom: 16px; font-weight: 700; }
    p { color: #999; font-size: 15px; line-height: 1.8; }
    .icon { font-size: 48px; margin-bottom: 16px; }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">✅</div>
    <h1>با موفقیت خارج شدید</h1>
    <p>می‌توانید این صفحه را ببندید و به Claude برگردید.</p>
  </div>
</body>
</html>`);
});

app.listen(LOGIN_PORT, "127.0.0.1", () => {
  console.log(`✅ Auxiliary server running on 127.0.0.1:${LOGIN_PORT}`);
});
