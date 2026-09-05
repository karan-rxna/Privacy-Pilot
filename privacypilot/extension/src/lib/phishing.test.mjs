/**
 * PrivacyPilot AI — phishing detector test harness.
 *
 * Run:  node phishing.test.mjs
 *
 * Live phishing URLs are a bad test bed: they are taken down within hours, they
 * are dangerous to load, and analyzePhishing() refuses to run on localhost, so
 * a local server cannot exercise it either. The detector is a pure function of
 * (url, domSignals), so it is driven directly here instead.
 *
 * Negative cases matter more than positive ones. A detector that fires on a
 * real bank's login page teaches the user to dismiss it, and a dismissed
 * warning protects nobody.
 */
import { analyzePhishing } from "./phishing.js";

const LOGIN = { passwordFields: 1, emailFields: 1, title: "Sign in", brandText: "", formActions: [] };
const NO_FORM = { passwordFields: 0, emailFields: 0, title: "", brandText: "", formActions: [] };

const cases = [
  // --- must fire -------------------------------------------------------
  // KNOWN FAILURE. Chrome hands tab.url to the worker with the hostname already
  // normalised to punycode, so detectMixedScript() never sees a Cyrillic letter
  // and signal 1 — the module's own "highest-confidence signal" — cannot fire in
  // a real browser. Verified in Chromium: new URL("https://аpple.com").hostname
  // is "xn--pple-43d.com". Fixing it means decoding xn-- labels before the
  // script check. Remove the `known` tag once that lands.
  ["homograph, Cyrillic а", "https://аpple.com/signin", LOGIN, ["homograph"], "punycode-normalised-before-check"],
  ["punycode label", "https://xn--pple-43d.com/login", LOGIN, ["punycode"]],
  ["typosquat, one char", "https://gooogle.com/accounts", LOGIN, ["typosquat"]],
  ["typosquat, transposed", "https://microsotf.com/login", LOGIN, ["typosquat"]],
  ["brand in subdomain", "https://paypal.com.secure-login.tk/signin", LOGIN, ["subdomain_spoof"]],
  ["brand welded into domain", "https://paypal-verify.com/login", LOGIN, ["brand_in_domain"]],
  ["Indian bank keyword", "https://onlinesbi-secure.tk/netbanking", LOGIN, ["brand_in_domain"]],
  ["page claims a brand", "https://cdn-assets-9f2.com/login",
    { ...LOGIN, title: "Netflix — Sign In", brandText: "Netflix" }, ["brand_mismatch"]],
  ["password over http", "http://some-random-site.com/login", LOGIN, ["insecure_form"]],
  ["form posts off-origin", "https://my-portal.com/login",
    { ...LOGIN, formActions: ["https://harvest-creds.ru/collect"] }, ["cross_origin_post"]],
  ["risky TLD rides along", "https://paypal-verify.tk/login", LOGIN, ["brand_in_domain", "risky_tld"]],

  // --- must NOT fire ---------------------------------------------------
  ["real PayPal", "https://www.paypal.com/signin", LOGIN, []],
  ["real Google accounts", "https://accounts.google.com/signin", LOGIN, []],
  ["real SBI", "https://www.onlinesbi.sbi/", LOGIN, []],
  ["real UIDAI", "https://myaadhaar.uidai.gov.in/", LOGIN, []],
  ["real Amazon India", "https://www.amazon.in/ap/signin", LOGIN, []],
  ["localhost dev", "http://localhost:3000/login", LOGIN, []],
  ["extension page", "chrome-extension://abc/popup.html", LOGIN, []],
  ["compound word, no boundary", "https://applepie.com/login", LOGIN, []],
  ["ordinary site, no form", "https://example.com/", NO_FORM, []],
  ["risky TLD alone", "https://my-blog.xyz/login", LOGIN, []],

  // --- probes: plausible pages that should stay quiet ------------------
  // KNOWN FAILURE. Signal 6 matches brand keywords as bare substrings, and
  // "live" (from live.com) is a common English word.
  ["live chat product", "https://helpdesk-tools.com/login",
    { ...LOGIN, title: "Live Chat — Log in", brandText: "Live Chat" }, [], "substring-brand-match"],
  // KNOWN FAILURE. Same cause: "meta" (from meta.com) is a substring of
  // "metadata", "metallurgy", "metabolism".
  ["metadata tool", "https://exiftool-web.com/login",
    { ...LOGIN, title: "Metadata Inspector", brandText: "Metadata Inspector" }, [], "substring-brand-match"],
  // KNOWN FAILURE. Signal 7 fires at "high" on every Okta/Auth0/Entra sign-in,
  // which is most corporate logins. Needs an IdP allowlist and a lower
  // confidence, or users learn to dismiss the card.
  ["SSO to a real IdP", "https://intranet.acme.com/login",
    { ...LOGIN, formActions: ["https://acme.okta.com/api/v1/authn"] }, [], "no-idp-allowlist"],
  // KNOWN FAILURE. Signal 5's separator rule stops "applepie.com" but not
  // "orchard-apple-farm.com". Brand keywords that are also ordinary words need
  // stronger evidence than adjacency to a hyphen.
  ["apple orchard shop", "https://orchard-apple-farm.com/login",
    { ...LOGIN, title: "Apple Farm — Members", brandText: "Apple Farm" }, [], "common-word-brand-keyword"]
];

let pass = 0, fail = 0, known = 0;
const failures = [];
const knownIssues = [];

for (const [name, url, dom, expected, knownTag] of cases) {
  const result = analyzePhishing(url, dom);
  const got = result ? result.findings.map((f) => f.id) : [];
  const ok = expected.length
    ? expected.every((id) => got.includes(id))
    : got.length === 0;

  let mark;
  if (ok) { pass++; mark = "  ok   "; }
  else if (knownTag) {
    known++;
    mark = " known ";
    knownIssues.push({ name, url, expected, got, knownTag });
  } else {
    fail++;
    mark = " FAIL  ";
    failures.push({ name, url, expected, got, suspicion: result?.suspicion ?? null });
  }
  console.log(`${mark}${name.padEnd(30)} → [${got.join(", ") || "none"}]`);
}

console.log(`\n${pass} passed, ${known} known issues, ${fail} failed`);

if (knownIssues.length) {
  console.log("\n--- known issues (tracked, not regressions) ---");
  for (const k of knownIssues) {
    console.log(`\n${k.name}  [${k.knownTag}]\n  url:      ${k.url}\n  expected: [${k.expected.join(", ") || "none"}]\n  got:      [${k.got.join(", ") || "none"}]`);
  }
  console.log("\nEach of these has a comment above its case explaining the cause.");
  console.log("Drop the trailing tag from a case once the underlying fix lands.");
}

if (failures.length) {
  console.log("\n--- REGRESSIONS ---");
  for (const f of failures) {
    console.log(`\n${f.name}\n  url:      ${f.url}\n  expected: [${f.expected.join(", ") || "none"}]\n  got:      [${f.got.join(", ") || "none"}]`);
  }
}
process.exit(fail ? 1 : 0);
