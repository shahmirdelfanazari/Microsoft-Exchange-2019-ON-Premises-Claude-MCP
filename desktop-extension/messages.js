// Messages shown by the desktop extension itself (the server's own replies come from ../locales).
// Chosen by the "Language" setting at install time (UI_LANGUAGE): "en" or "fa".
const en = {
  browserOpened: "🔐 A browser window opened. Sign in, then try again.",
  loginRequired: "🔐 **Login required**\n\nA browser window has opened. Come back and try again after logging in.",
  authFailed: "❌ Authentication failed. Please try again.",
  notConfigured: "❌ The extension has no server URL. Open this extension in Claude Desktop's Extensions settings (Settings → Desktop app → Extensions), choose Configure and enter your server URL.",
  discoveryFailed: why => `❌ Could not reach the server's sign-in settings (${why}). Check the server URL in the extension settings and your network/VPN.`,
  notSent: why => `❌ Could not connect to the server (${why}). Nothing was done; try again in a moment.`,
  noAnswerSafe: why => `❌ The server did not answer (${why}). Please try again.`,
  noAnswerUnsafe: why => `⚠️ The server's answer did not arrive (${why}) — the action may have been done. Check with list_events (or your mailbox) before repeating it, so nothing is created twice.`,
  tooManyRequests: "⏳ Too many requests. Wait a minute, then try again.",
  loggedOut: "✅ Logged out.",
};

const fa = {
  browserOpened: "🔐 مرورگر باز شد — بعد از لاگین دوباره امتحان کن.",
  loginRequired: "🔐 **ورود لازم است**\n\nمرورگر باز شد. بعد از ورود برگرد و دوباره امتحان کن.",
  authFailed: "❌ احراز هویت ناموفق بود. دوباره امتحان کن.",
  notConfigured: "❌ آدرس سرور در افزونه تنظیم نشده است. در Claude Desktop به Settings → Desktop app → Extensions بروید، این افزونه را باز کنید و آدرس سرور را وارد کنید.",
  discoveryFailed: why => `❌ تنظیمات ورود از سرور دریافت نشد (${why}). آدرس سرور در تنظیمات افزونه و اتصال شبکه/VPN را بررسی کن.`,
  notSent: why => `❌ اتصال به سرور برقرار نشد (${why}). هیچ عملیاتی انجام نشد؛ کمی بعد دوباره تلاش کن.`,
  noAnswerSafe: why => `❌ سرور پاسخ نداد (${why}). لطفاً دوباره تلاش کن.`,
  noAnswerUnsafe: why => `⚠️ پاسخ سرور نرسید (${why}) — ممکن است این عملیات انجام شده باشد. قبل از تکرار، با list_events (یا صندوق ایمیل) بررسی کن؛ کورکورانه تکرار نکن تا تکراری ثبت نشود.`,
  tooManyRequests: "⏳ تعداد درخواست‌ها زیاد است. یک دقیقه صبر کن و دوباره امتحان کن.",
  loggedOut: "✅ خارج شدی.",
};

export const M = (process.env.UI_LANGUAGE || "").trim().toLowerCase() === "fa" ? fa : en;
