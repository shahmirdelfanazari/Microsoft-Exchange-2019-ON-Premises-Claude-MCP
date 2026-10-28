// Picks the user-facing language from UI_LANGUAGE (see config.js).
import { UI_LANGUAGE } from "./config.js";
import en from "./locales/en.js";
import fa from "./locales/fa.js";

const LOCALES = { en, fa };

if (!LOCALES[UI_LANGUAGE]) {
  console.error(`❌ Unsupported UI_LANGUAGE "${UI_LANGUAGE}" — use one of: ${Object.keys(LOCALES).join(", ")}`);
  process.exit(1);
}

export const T = LOCALES[UI_LANGUAGE];
