// PrivacyPilot - risk scoring (ES module, imported by background.js).
// Renamed from "risk Engine.js" - the space broke imports and packaging - and
// the stray test call at the bottom of that file has been removed.

const WEIGHTS = {
  location: 15,
  screen: 15,
  camera: 10,
  microphone: 10,
  clipboard: 5,
  canvas: 5,
  notifications: 3
};

// Repeat requests of the same kind matter, but with diminishing returns.
const REPEAT_FACTOR = 0.35;
const MAX_PER_TYPE = 30;

const PHISHING_PENALTY = { high: 40, medium: 20, low: 8 };

/**
 * @param {Array<{type:string,count?:number}>} events
 * @param {Array<{severity:string}>} [phishingFindings]
 * @returns {number} 0-100, higher is safer
 */
export function calculateRisk(events, phishingFindings) {
  let score = 100;

  const byType = new Map();
  for (const event of events || []) {
    if (!event || !WEIGHTS[event.type]) continue;
    byType.set(event.type, (byType.get(event.type) || 0) + (event.count || 1));
  }

  for (const [type, count] of byType) {
    const base = WEIGHTS[type];
    const penalty = base + base * REPEAT_FACTOR * Math.max(0, count - 1);
    score -= Math.min(penalty, MAX_PER_TYPE);
  }

  for (const finding of phishingFindings || []) {
    score -= PHISHING_PENALTY[finding && finding.severity] || 10;
  }

  return Math.max(0, Math.min(100, Math.round(score)));
}

/** @returns {"safe"|"caution"|"risky"} */
export function riskBand(score) {
  if (score >= 75) return "safe";
  if (score >= 45) return "caution";
  return "risky";
}

export function riskColor(score) {
  return { safe: "#1a9c5b", caution: "#c98a00", risky: "#d0342c" }[riskBand(score)];
}
