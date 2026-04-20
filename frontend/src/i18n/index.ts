// CMMC trim-1: this module used to orchestrate 30+ locales and the
// dayjs locale for each one. A US DIB cabinet ships English only —
// the old file was ~195 lines of BCP 47 fuzzy-matching and dynamic
// dayjs locale imports, all dead weight in the embedded bundle.
//
// Keeping the public surface (default export, isRtl, setLocale,
// setHtmlLocale) so nothing in the SPA has to change.

import dayjs from "dayjs";
import "dayjs/locale/en";
import { createI18n } from "vue-i18n";

import en from "./en.json";

const messages = {
  en,
};

dayjs.locale("en");

export const i18n = createI18n({
  locale: "en",
  fallbackLocale: "en",
  messages,
  legacy: true,
});

// Always-false in an English-only build; kept so callers don't have
// to know this is a one-locale deployment.
export const isRtl = (_locale?: string) => false;

export function setLocale(_locale: string) {
  // No-op — this deployment is en-only. If a future build needs
  // multi-locale support, restore the fuzzy-matcher from git
  // history (commit before the trim-1 cleanup).
}

export function setHtmlLocale(_locale: string) {
  const html = document.documentElement;
  html.lang = "en";
  html.dir = "ltr";
}

// Legacy stub for callers that used to detect browser locale.
export const detectLocale = () => "en";

export default i18n;
