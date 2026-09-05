/**
 * What each kind of tracking actually does to the person reading this.
 *
 * Copy rules, because the overlay lives or dies on tone:
 *  - Describe the mechanism, not a feeling. "Records what you type" beats
 *    "puts your privacy at risk."
 *  - No scare words. No "dangerous", no "attack", no red-alert language for
 *    an analytics script. Overstating the small stuff means nobody believes
 *    you about the big stuff.
 *  - Second person, present tense, one sentence where possible.
 */

export const SEVERITY = { critical: 3, high: 2, moderate: 1, low: 0 };

export const TRACKER_HARMS = {
  session: {
    severity: "critical",
    headline: "This page is recording your session",
    harm:
      "Scrolling, mouse movement, and text you type into forms are being recorded — including text you type and then delete before submitting.",
    who: (names) => `${names.join(", ")} can replay your visit as a video.`
  },
  fingerprint: {
    severity: "critical",
    headline: "You are being fingerprinted",
    harm:
      "Your GPU, fonts, and canvas rendering are being read to build a device signature. This identifies you even after you clear cookies or open a private window.",
    who: (names) => `${names.join(", ")} is generating the signature.`
  },
  advertising: {
    severity: "high",
    headline: "Ad networks are watching this visit",
    harm:
      "These companies sit on thousands of other sites too. They link what you look at here to your browsing elsewhere and build a profile from it.",
    who: (names) => `${names.join(", ")} received a request from this page.`
  },
  social: {
    severity: "high",
    headline: "A social platform was told you are here",
    harm:
      "This fires whether or not you have an account, and whether or not you are logged in. It attaches this page to your advertising profile.",
    who: (names) => `${names.join(", ")} was notified.`
  },
  analytics: {
    severity: "moderate",
    headline: "Analytics are running",
    harm:
      "Your visit is being measured. This is normal and usually the site's own measurement, but the data does leave your browser.",
    who: (names) => `${names.join(", ")} is collecting it.`
  }
};

export const PERMISSION_HARMS = {
  microphone: "Audio capture from your device, at any time the tab is open.",
  camera: "Video capture from your device, at any time the tab is open.",
  "screen capture": "A recording of whatever is on your screen, not just this tab.",
  "clipboard read": "Whatever you last copied — often a password, an address, or a card number.",
  "location (continuous)": "Your position, updated continuously while the tab stays open.",
  "location (high accuracy)": "Your position to within a few metres, not just your city.",
  location: "Your physical position.",
  notifications: "A durable channel to message you later, commonly reused for marketing.",
  bluetooth: "Access to nearby devices you have paired.",
  "usb device": "Direct access to hardware you plug in."
};

/**
 * Decide whether a page warrants interrupting the user, and with what.
 * Returns null when it does not — silence is the default.
 */
export function buildAlert(state, result) {
  const groups = {};
  for (const t of state.trackers || []) {
    (groups[t.category] ||= new Set()).add(t.name);
  }

  const findings = [];

  for (const [category, spec] of Object.entries(TRACKER_HARMS)) {
    const names = groups[category];
    if (!names) continue;
    // Analytics alone is not worth an interruption.
    if (category === "analytics" && Object.keys(groups).length === 1) continue;
    if (category === "advertising" && names.size < 3) continue;
    findings.push({
      kind: "tracker",
      category,
      severity: spec.severity,
      headline: spec.headline,
      harm: spec.harm,
      who: spec.who([...names]),
      hosts: (state.trackers || [])
        .filter((t) => t.category === category)
        .map((t) => t.host)
    });
  }

  const fpSurfaces = new Set(
    (state.events || []).filter((e) => e.kind === "fingerprint").map((e) => e.detail)
  );
  if (fpSurfaces.size >= 2 && !findings.some((f) => f.category === "fingerprint")) {
    findings.push({
      kind: "tracker",
      category: "fingerprint",
      severity: "critical",
      headline: TRACKER_HARMS.fingerprint.headline,
      harm: TRACKER_HARMS.fingerprint.harm,
      who: `Read from ${[...fpSurfaces].join(", ")}.`,
      hosts: []
    });
  }

  for (const p of result.permissions || []) {
    if (p.recommendation !== "deny") continue;
    findings.push({
      kind: "permission",
      detail: p.detail,
      severity: p.level === "high" ? "critical" : "high",
      headline: `${p.label} requested without an obvious reason`,
      harm: PERMISSION_HARMS[p.detail] || "Access your device does not appear to need.",
      who: `A ${result.siteType} site does not normally need this.`
    });
  }

  if (!findings.length) return null;

  findings.sort((a, b) => SEVERITY[b.severity] - SEVERITY[a.severity]);
  return {
    score: result.score,
    hostname: state.hostname,
    findings: findings.slice(0, 3),
    blockableHosts: [...new Set(findings.flatMap((f) => f.hosts || []))]
  };
}
