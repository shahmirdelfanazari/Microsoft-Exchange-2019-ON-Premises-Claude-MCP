// Auxiliary HTTP server (bound to 127.0.0.1:LOGIN_PORT, exposed by the reverse proxy under /auth/).
// - /oauth-callback  receives the OIDC authorization code for desktop-extension style clients
// - /poll-token      lets such a client exchange that code (PKCE) for tokens
// - /dl-file/:id     serves attachments that get_attachments wrote to /tmp (10-minute links)
// - /logged-out      landing page after OIDC logout
import express from "express";
import rateLimit from "express-rate-limit";
import { readFileSync, unlinkSync } from "fs";
import { OIDC_AUTH_BASE, LOGIN_PORT } from "./config.js";
import { T } from "./i18n.js";

const app = express();
// Behind the local reverse proxy: take the client address from X-Forwarded-For
app.set("trust proxy", "loopback");
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(rateLimit({ windowMs: 60 * 1000, limit: 60, standardHeaders: "draft-8", legacyHeaders: false }));

// ── Attachment downloads ──
// get_attachments (index.js, same process) registers each file here; the download
// route only serves registered entries, so no path is ever built from the request.
const downloads = new Map(); // id -> { file, name, contentType }
const DOWNLOAD_TTL_MS = 10 * 60 * 1000;

export function registerDownload(id, file, name, contentType) {
  downloads.set(id, { file, name, contentType });
  setTimeout(() => {
    downloads.delete(id);
    try { unlinkSync(file); } catch {}
  }, DOWNLOAD_TTL_MS).unref();
}

app.get("/dl-file/:shortId", (req, res) => {
  const entry = downloads.get(req.params.shortId);
  if (!entry) return res.status(404).send("File not found or expired (links valid for 10 minutes).");
  try {
    const buffer = readFileSync(entry.file);
    res.setHeader("Content-Type", entry.contentType || "application/octet-stream");
    res.setHeader("Content-Disposition", `attachment; filename*=UTF-8''${encodeURIComponent(entry.name || "file")}`);
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
  res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><style>body{font-family:Vazirmatn,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#1a1a1a;color:#f0c040;direction:${T.dir}}</style></head><body><div style="text-align:center"><h1>✅ ${T.loginOkTitle}</h1><p style="color:#ccd6f6">${T.loginOkText}</p></div></body></html>`);
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
<html dir="${T.dir}" lang="${T.lang}">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${T.logoutTitle}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Vazirmatn','Segoe UI',Tahoma,sans-serif; background: #1a1a1a; min-height: 100vh; display: flex; align-items: center; justify-content: center; direction: ${T.dir}; }
    .card { background: #242424; border: 1px solid #333; border-radius: 16px; padding: 40px; width: 100%; max-width: 400px; text-align: center; }
    h1 { color: #f0c040; font-size: 24px; margin-bottom: 16px; font-weight: 700; }
    p { color: #999; font-size: 15px; line-height: 1.8; }
    .icon { font-size: 48px; margin-bottom: 16px; }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">✅</div>
    <h1>${T.logoutHeading}</h1>
    <p>${T.logoutText}</p>
  </div>
</body>
</html>`);
});

app.listen(LOGIN_PORT, "127.0.0.1", () => {
  console.log(`✅ Auxiliary server running on 127.0.0.1:${LOGIN_PORT}`);
});
