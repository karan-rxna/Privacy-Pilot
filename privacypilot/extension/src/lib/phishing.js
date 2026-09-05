/**
 * PrivacyPilot AI — phishing signals.
 *
 * DESIGN RULE, and it is not negotiable: this module can raise suspicion. It can
 * never certify safety. There is no "looks legitimate" return value, no green
 * state, no score above zero meaning "fine". It returns findings or it returns
 * null, and null means "nothing detected", which is not the same as "safe".
 *
 * The reason is asymmetric harm. A missed phishing site with no warning leaves
 * the user exactly as cautious as they were. A missed phishing site with a green
 * badge has actively disarmed them. Any feature that can display reassurance is
 * a feature that can get someone's account stolen, so it does not exist here.
 *
 * Chrome's Safe Browsing already handles URL blocklists, domain reputation, and
 * WHOIS age far better than an extension can. This module deliberately targets
 * only what Safe Browsing is weakest at: freshly registered domains using
 * *visual* deception, where the signal is in the rendering rather than in any
 * reputation database.
 */

/* ------------------------------------------------------------------ */
/* Brands that are actually impersonated, with their legitimate domains */
/* ------------------------------------------------------------------ */

const BRANDS = [
  { name: "Google", domains: ["google.com", "google.co.in", "youtube.com", "gmail.com"] },
  { name: "Microsoft", domains: ["microsoft.com", "live.com", "outlook.com", "office.com", "microsoftonline.com"] },
  { name: "Apple", domains: ["apple.com", "icloud.com"] },
  { name: "Amazon", domains: ["amazon.com", "amazon.in", "amazon.co.uk"] },
  { name: "Meta", domains: ["facebook.com", "instagram.com", "meta.com", "whatsapp.com"] },
  { name: "PayPal", domains: ["paypal.com"] },
  { name: "Netflix", domains: ["netflix.com"] },
  { name: "LinkedIn", domains: ["linkedin.com"] },
  { name: "DHL", domains: ["dhl.com", "dhl.de"] },
  { name: "FedEx", domains: ["fedex.com"] },
  { name: "Steam", domains: ["steampowered.com", "steamcommunity.com"] },
  { name: "Binance", domains: ["binance.com"] },
  { name: "Coinbase", domains: ["coinbase.com"] },
  { name: "State Bank of India", domains: ["onlinesbi.sbi", "sbi.co.in"] },
  { name: "HDFC Bank", domains: ["hdfcbank.com"] },
  { name: "ICICI Bank", domains: ["icicibank.com"] },
  { name: "Axis Bank", domains: ["axisbank.com"] },
  { name: "Paytm", domains: ["paytm.com"] },
  { name: "PhonePe", domains: ["phonepe.com"] },
  { name: "Flipkart", domains: ["flipkart.com"] },
  { name: "Aadhaar / UIDAI", domains: ["uidai.gov.in"] },
  { name: "Income Tax India", domains: ["incometax.gov.in"] }
];

/** TLDs disproportionately represented in phishing. Weak signal on its own. */
const RISKY_TLDS = new Set([
  "tk", "ml", "ga", "cf", "gq", "top", "xyz", "buzz", "click",
  "link", "work", "rest", "cam", "sbs", "cfd", "icu"
]);

/* ------------------------------------------------------------------ */
/* Primitives                                                          */
/* ------------------------------------------------------------------ */

/** Registrable domain, approximated. Handles the common two-part public suffixes. */
export function registrableDomain(hostname) {
  const parts = hostname.toLowerCase().replace(/\.$/, "").split(".");
  if (parts.length <= 2) return parts.join(".");
  const twoPartSuffixes = new Set([
    "co.in", "co.uk", "com.au", "co.jp", "com.br", "co.za",
    "gov.in", "ac.in", "net.in", "org.in", "com.sg", "co.nz"
  ]);
  const lastTwo = parts.slice(-2).join(".");
  return twoPartSuffixes.has(lastTwo) ? parts.slice(-3).join(".") : lastTwo;
}

/** Levenshtein distance, capped early for speed. */
function editDistance(a, b, cap = 3) {
  if (Math.abs(a.length - b.length) > cap) return cap + 1;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const curr = [i];
    let rowMin = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost);
      rowMin = Math.min(rowMin, curr[j]);
    }
    if (rowMin > cap) return cap + 1;
    prev = curr;
  }
  return prev[b.length];
}

/**
 * Detect mixed writing systems in a label.
 *
 * This is the highest-confidence signal in the whole module. "аpple.com" with a
 * Cyrillic а renders pixel-identically to the real thing, and there is no
 * legitimate reason for a single domain label to mix Cyrillic or Greek letters
 * with Latin ones. Genuinely non-Latin domains are fine — they are consistently
 * one script, and that is what we check for.
 */
function detectMixedScript(hostname) {
  const scripts = {
    latin: /[a-z]/i,
    cyrillic: /[\u0400-\u04FF]/,
    greek: /[\u0370-\u03FF]/,
    armenian: /[\u0530-\u058F]/
  };

  for (const label of hostname.split(".")) {
    const present = Object.entries(scripts)
      .filter(([, re]) => re.test(label))
      .map(([name]) => name);
    if (present.length > 1) {
      return { label, scripts: present };
    }
  }
  return null;
}

/** Punycode-encoded labels, which is how homographs reach the wire. */
function detectPunycode(hostname) {
  const labels = hostname.split(".").filter((l) => l.startsWith("xn--"));
  return labels.length ? labels : null;
}

/* ------------------------------------------------------------------ */
/* Signals                                                             */
/* ------------------------------------------------------------------ */

/**
 * @param {string} url          the page URL
 * @param {object} dom          facts gathered by the content script
 * @param {number} dom.passwordFields
 * @param {number} dom.emailFields
 * @param {string} dom.title
 * @param {string} dom.brandText   visible text likely to name a brand
 * @param {string[]} dom.formActions absolute URLs each form posts to
 */
export function analyzePhishing(url, dom = {}) {
  let hostname, protocol;
  try {
    const parsed = new URL(url);
    hostname = parsed.hostname.toLowerCase();
    protocol = parsed.protocol;
  } catch {
    return null;
  }

  // Never analyse the browser's own pages or local development.
  if (!/^https?:$/.test(protocol)) return null;
  if (["localhost", "127.0.0.1", "[::1]"].includes(hostname)) return null;

  const domain = registrableDomain(hostname);
  const hasCredentialForm = (dom.passwordFields || 0) > 0;
  const findings = [];

  /* --- 1. Mixed script. Near-zero false positive rate. --------------- */
  const mixed = detectMixedScript(hostname);
  if (mixed) {
    findings.push({
      id: "homograph",
      confidence: "high",
      headline: "This address uses lookalike characters",
      detail:
        `The part of the address reading "${mixed.label}" mixes ${mixed.scripts.join(" and ")} letters. ` +
        `Some characters look identical to Latin ones but are different characters entirely. ` +
        `This is how a fake address is made to look like a real one.`,
      advice: "Do not enter anything here. Reach the site by typing the address yourself or using a bookmark."
    });
  }

  /* --- 2. Punycode. ------------------------------------------------- */
  const puny = detectPunycode(hostname);
  if (puny && !mixed) {
    findings.push({
      id: "punycode",
      confidence: hasCredentialForm ? "high" : "medium",
      headline: "This address is encoded, not what it displays",
      detail:
        `The address contains ${puny.join(", ")}, an encoding that lets non-Latin characters ` +
        `appear in a domain name. This is legitimate for genuinely non-English sites, but it is ` +
        `also the standard way a fake address is disguised.`,
      advice: "Check the address bar carefully before typing anything."
    });
  }

  /* --- 3. Typosquatting. -------------------------------------------- */
  const bare = domain.replace(/\.[a-z.]+$/, "");
  for (const brand of BRANDS) {
    if (brand.domains.includes(domain)) break; // legitimate; stop checking

    for (const legit of brand.domains) {
      const legitBare = legit.replace(/\.[a-z.]+$/, "");
      if (bare === legitBare) continue;
      const distance = editDistance(bare, legitBare, 2);
      if (distance > 0 && distance <= 2 && legitBare.length >= 5) {
        findings.push({
          id: "typosquat",
          confidence: hasCredentialForm ? "high" : "medium",
          headline: `This address closely resembles ${legit}`,
          detail:
            `You are on ${domain}. The real ${brand.name} address is ${legit}. ` +
            `These differ by ${distance} character${distance > 1 ? "s" : ""}, which is easy to miss.`,
          advice: `If you meant to visit ${brand.name}, close this and go to ${legit} directly.`
        });
        break;
      }
    }
    if (findings.some((f) => f.id === "typosquat")) break;
  }

  /* --- 4. Brand name in a subdomain, not the real domain. ----------- */
  // paypal.com.secure-login.tk — the brand appears, but not where it counts.
  const subdomainPart = hostname.slice(0, hostname.length - domain.length);
  for (const brand of BRANDS) {
    if (brand.domains.includes(domain)) break;
    // Bounded match, same reasoning as signal 5: an unbounded substring test
    // fires on "mygoogleclone-docs", which is not a spoof of anything.
    const hit = brand.domains
      .map((d) => d.split(".")[0])
      .filter((k) => k.length >= 5)
      .find((k) => new RegExp(`(^|[-_.0-9])${k}([-_.0-9]|$)`, "i").test(subdomainPart));
    if (hit && subdomainPart.length > 0) {
      findings.push({
        id: "subdomain_spoof",
        confidence: hasCredentialForm ? "high" : "medium",
        headline: `"${hit}" appears in the address, but this is not ${brand.name}`,
        detail:
          `The site you are actually on is ${domain}. The ${brand.name} name appears earlier in ` +
          `the address, where anyone can put any text they like. Only the part just before the ` +
          `first slash identifies the real owner.`,
        advice: `Read the address from the right. The owner is ${domain}, not ${brand.name}.`
      });
      break;
    }
  }

  /* --- 5. Brand keyword welded into the domain itself. -------------- */
  // "onlinesbi-secure.tk", "paypal-verify.com". Distinct from signal 4, where
  // the brand sits in a subdomain. Here it is inside the registrable domain.
  //
  // The separator requirement is what keeps this from firing on legitimate
  // compound words: "applepie.com" has no boundary after "apple", so it is
  // ignored, while "apple-support.com" is not. Combined with the credential-form
  // requirement, the false positive rate stays acceptable.
  if (hasCredentialForm && !findings.some((f) => f.id === "typosquat" || f.id === "subdomain_spoof")) {
    for (const brand of BRANDS) {
      if (brand.domains.some((d) => domain === d || domain.endsWith(`.${d}`))) break;

      const keywords = brand.domains
        .map((d) => d.split(".")[0])
        .filter((k) => k.length >= 5);

      for (const keyword of keywords) {
        // Keyword must sit next to a separator, a digit, or a string boundary.
        const bounded = new RegExp(`(^|[-_.0-9])${keyword}([-_.0-9]|$)`, "i");
        if (bounded.test(bare)) {
          findings.push({
            id: "brand_in_domain",
            confidence: "high",
            headline: `"${keyword}" is in this address, but this is not ${brand.name}`,
            detail:
              `The real ${brand.name} address is ${brand.domains[0]}. This page is on ${domain}, ` +
              `which merely contains the name. Anyone can register a domain with a company's name in it.`,
            advice: `If you meant to sign in to ${brand.name}, go to ${brand.domains[0]} directly.`
          });
          break;
        }
      }
      if (findings.some((f) => f.id === "brand_in_domain")) break;
    }
  }

  /* --- 6. Page claims a brand its domain contradicts. --------------- */
  if (hasCredentialForm) {
    const haystack = `${dom.title || ""} ${dom.brandText || ""}`.toLowerCase();
    for (const brand of BRANDS) {
      if (brand.domains.some((d) => domain === d || domain.endsWith(`.${d}`))) break;
      const claimsBrand =
        haystack.includes(brand.name.toLowerCase()) ||
        brand.domains.some((d) => haystack.includes(d.split(".")[0]));
      if (claimsBrand && !findings.some((f) =>
        f.id === "typosquat" || f.id === "subdomain_spoof" || f.id === "brand_in_domain"
      )) {
        findings.push({
          id: "brand_mismatch",
          confidence: "medium",
          headline: `This page presents itself as ${brand.name}`,
          detail:
            `The page names ${brand.name} and asks for a password, but it is hosted on ${domain}, ` +
            `which is not an address ${brand.name} uses.`,
          advice: `Sign in through ${brand.domains[0]} instead.`
        });
        break;
      }
    }
  }

  /* --- 6. Password field over plain HTTP. --------------------------- */
  if (hasCredentialForm && protocol === "http:") {
    findings.push({
      id: "insecure_form",
      confidence: "high",
      headline: "This password field is not encrypted",
      detail:
        "Anything you type here travels in readable form across the network. Anyone sharing " +
        "this Wi-Fi, and every network in between, can read it.",
      advice: "Do not enter a password on this page."
    });
  }

  /* --- 7. Credential form posting to a different origin. ------------ */
  if (hasCredentialForm) {
    for (const action of dom.formActions || []) {
      try {
        const target = registrableDomain(new URL(action).hostname);
        if (target && target !== domain) {
          findings.push({
            id: "cross_origin_post",
            confidence: "high",
            headline: "This form sends your details to a different site",
            detail:
              `The login form on ${domain} submits to ${target}. Legitimate sign-in pages ` +
              `occasionally use a separate identity provider, but this is also exactly what a ` +
              `credential-harvesting page does.`,
            advice: "Unless you recognise the second address as the site's own login provider, do not submit."
          });
          break;
        }
      } catch {}
    }
  }

  /* --- 8. Risky TLD. Only ever counts alongside something else. ----- */
  const tld = domain.split(".").pop();
  if (RISKY_TLDS.has(tld) && hasCredentialForm && findings.length > 0) {
    findings.push({
      id: "risky_tld",
      confidence: "low",
      headline: `.${tld} domains are commonly used for short-lived fake sites`,
      detail:
        `This is a weak signal on its own — plenty of legitimate sites use .${tld}. ` +
        `It matters here because of the other findings above.`,
      advice: null
    });
  }

  if (!findings.length) return null;

  const order = { high: 3, medium: 2, low: 1 };
  findings.sort((a, b) => order[b.confidence] - order[a.confidence]);

  return {
    hostname,
    domain,
    hasCredentialForm,
    // Deliberately named for what it is. There is no inverse of this value.
    suspicion: findings[0].confidence,
    findings: findings.slice(0, 3)
  };
}
