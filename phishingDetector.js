// PrivacyPilot - phishing heuristics.
// Loaded in the ISOLATED world alongside content.js, which calls
// analyzePhishing() once the DOM exists (the original ran at document_start,
// where the password-field check could only ever see an empty document).

/* exported analyzePhishing */

const PP_BRANDS = [
  "paypal", "apple", "icloud", "microsoft", "office365", "outlook",
  "google", "gmail", "amazon", "netflix", "facebook", "instagram",
  "whatsapp", "binance", "coinbase", "metamask", "sbi", "hdfc", "icici",
  "axisbank", "paytm", "phonepe", "irctc", "aadhaar", "uidai"
];

// TLDs that show up disproportionately in phishing campaigns.
const PP_RISKY_TLDS = [
  "zip", "mov", "tk", "ml", "ga", "cf", "gq", "top", "xyz", "click",
  "country", "kim", "work", "rest", "cam", "quest"
];

function ppRegistrableDomain(hostname) {
  const parts = hostname.split(".").filter(Boolean);
  if (parts.length <= 2) return hostname;
  // Good enough without a public-suffix list: handle the common two-part
  // suffixes (co.uk, co.in, com.au ...).
  const twoPart = ["co", "com", "net", "org", "gov", "edu", "ac"];
  if (parts.length >= 3 && twoPart.includes(parts[parts.length - 2])) {
    return parts.slice(-3).join(".");
  }
  return parts.slice(-2).join(".");
}

function analyzePhishing() {
  const findings = [];
  const host = location.hostname.toLowerCase();
  const registrable = ppRegistrableDomain(host);

  function add(id, severity, message) {
    findings.push({ id, severity, message });
  }

  // 1. Punycode / internationalised domain used for look-alike characters.
  if (host.includes("xn--")) {
    add("punycode", "high", "Punycode domain - the address may imitate another site using look-alike characters.");
  }

  const passwordField = document.querySelector('input[type="password"]');

  // 2. Credentials over plaintext HTTP.
  if (passwordField && location.protocol === "http:") {
    add("http-password", "high", "Password field on an unencrypted (http://) page.");
  }

  // 3. Password form posting to a different origin.
  if (passwordField) {
    const form = passwordField.form;
    const action = form && form.getAttribute("action");
    if (action) {
      try {
        const target = new URL(action, location.href);
        if (target.origin !== location.origin) {
          add("cross-origin-form", "high", `Login form submits to a different site (${target.hostname}).`);
        }
      } catch (_) {
        /* malformed action - ignore */
      }
    }
  }

  // 4. A well-known brand name in the hostname, but not in the actual domain.
  //    e.g. paypal.secure-login.example.com
  const brand = PP_BRANDS.find(
    (b) => host.includes(b) && !registrable.startsWith(b + ".") && registrable !== b
  );
  if (brand) {
    add(
      "brand-in-subdomain",
      "high",
      `"${brand}" appears in the address but the real domain is ${registrable}.`
    );
  }

  // 5. Risky TLD combined with a login form.
  const tld = registrable.split(".").pop();
  if (passwordField && PP_RISKY_TLDS.includes(tld)) {
    add("risky-tld", "medium", `Login form on a .${tld} domain, a TLD commonly used for phishing.`);
  }

  // 6. Raw IP address instead of a domain name.
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    add("ip-host", "medium", "Site is served from a bare IP address rather than a domain name.");
  }

  // 7. Excessive hyphens / subdomain depth, a common obfuscation pattern.
  if (host.split(".").length > 4 || (host.match(/-/g) || []).length >= 4) {
    add("obfuscated-host", "low", "Unusually long or hyphen-heavy hostname.");
  }

  // 8. Password field inside a cross-origin iframe.
  if (passwordField && window.top !== window.self) {
    add("framed-login", "medium", "Login form is embedded inside a frame from another page.");
  }

  return findings.length ? findings : null;
}
