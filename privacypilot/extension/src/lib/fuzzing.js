function hashString(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

/**
 * A deterministic seed for one origin on this install.
 * @param {string} origin  e.g. "https://example.com"
 * @param {string} salt    per-install random string, generated once and stored
 */
export function seedFor(origin, salt) {
  return hashString(`${salt || "pp"}::${origin}`);
}

/** mulberry32 — tiny seeded PRNG. Same seed always yields the same sequence. */
export function rngFrom(seed) {
  let a = seed >>> 0;
  return function () {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/* ------------------------------------------------------------------ */
/* Location                                                            */
/* ------------------------------------------------------------------ */

/**
 * Grid sizes in degrees. Snapping to a grid beats adding an offset: an offset
 * still encodes the true position plus a constant, so anyone who learns the
 * constant recovers you exactly. A grid destroys the information outright —
 * every point in the cell maps to the same output.
 */
export const LOCATION_GRIDS = {
  precise: null,          // pass through untouched
  street: 0.001,          // ~110 m
  neighbourhood: 0.01,    // ~1.1 km
  city: 0.05,             // ~5.5 km
  region: 0.25            // ~27 km
};

/**
 * Return a degraded copy of a GeolocationPosition.
 *
 * The jitter inside the cell is seeded, so the answer never moves between calls
 * — but it stops the coordinate being an obviously round number, which is what
 * makes naive rounding detectable.
 *
 * @param {GeolocationPosition} position
 * @param {number} seed
 * @param {keyof LOCATION_GRIDS} level
 */
export function fuzzPosition(position, seed, level = "neighbourhood") {
  const grid = LOCATION_GRIDS[level];
  if (!grid) return position;

  const rand = rngFrom(seed);
  const c = position.coords;

  const snap = (value, offset) =>
    Math.round(value / grid) * grid + (offset - 0.5) * grid * 0.4;

  const latitude = Number(snap(c.latitude, rand()).toFixed(6));
  const longitude = Number(snap(c.longitude, rand()).toFixed(6));

  // Accuracy MUST be widened to match the grid. Reporting 20 m accuracy on a
  // coordinate that is 5 km off is the giveaway that betrays every naive
  // spoofer — a site can spot the contradiction immediately.
  const accuracy = Math.max(c.accuracy || 0, grid * 111000 * 0.5);

  return {
    coords: {
      latitude,
      longitude,
      accuracy,
      // Null out everything a coarse position cannot honestly claim to know.
      altitude: null,
      altitudeAccuracy: null,
      heading: null,
      speed: null
    },
    timestamp: position.timestamp
  };
}

/* ------------------------------------------------------------------ */
/* Canvas fingerprinting                                               */
/* ------------------------------------------------------------------ */

/**
 * Perturb a handful of pixels by ±1 in one channel.
 *
 * Blocking canvas outright breaks real features — charts, image editors, PDF
 * rendering. Instead we make the readback useless as an identifier while
 * leaving it visually identical. A ±1 change in one channel of a few hundred
 * pixels is imperceptible but changes the hash completely.
 *
 * Mutates the array in place.
 */
export function perturbPixels(data, seed, samples = 240) {
  if (!data || !data.length) return data;
  const rand = rngFrom(seed);
  const pixelCount = data.length / 4;

  for (let i = 0; i < samples; i++) {
    const pixel = Math.floor(rand() * pixelCount);
    const channel = Math.floor(rand() * 3);        // R, G or B — never alpha
    const index = pixel * 4 + channel;
    const delta = rand() < 0.5 ? -1 : 1;
    const next = data[index] + delta;
    if (next >= 0 && next <= 255) data[index] = next;
  }
  return data;
}

/* ------------------------------------------------------------------ */
/* Device entropy                                                      */
/* ------------------------------------------------------------------ */

/**
 * Common GPU strings. The aim is to blend into a crowd, not to be unique — so
 * we pick from a small set of very ordinary values rather than inventing one.
 */
const COMMON_RENDERERS = [
  "ANGLE (Intel, Intel(R) UHD Graphics (0x00009A49) Direct3D11 vs_5_0 ps_5_0, D3D11)",
  "ANGLE (Intel, Intel(R) HD Graphics 620 Direct3D11 vs_5_0 ps_5_0, D3D11)",
  "ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 Direct3D11 vs_5_0 ps_5_0, D3D11)",
  "ANGLE (AMD, AMD Radeon(TM) Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)"
];

export function genericRenderer(seed) {
  return COMMON_RENDERERS[seed % COMMON_RENDERERS.length];
}

export function genericVendor() {
  return "Google Inc. (Intel)";
}

/**
 * Normalised hardware values. Each contributes little entropy alone, but they
 * combine — and the most common value is the safest answer.
 */
export const NORMALISED = {
  hardwareConcurrency: 8,
  deviceMemory: 8
};

/* ------------------------------------------------------------------ */
/* Modes                                                               */
/* ------------------------------------------------------------------ */

/**
 * Per-site setting. "approximate" is the default because it is the only one
 * that protects without breaking pages — and a privacy tool people disable
 * because it broke a checkout protects nobody.
 */
export const MODES = {
  precise: { id: "precise", label: "Precise", detail: "Real values. Nothing is changed." },
  approximate: { id: "approximate", label: "Approximate", detail: "Coarse location, scrambled fingerprint." },
  denied: { id: "denied", label: "Denied", detail: "The request fails as if you clicked Block." }
};

export const DEFAULT_MODE = "approximate";
export const DEFAULT_LOCATION_LEVEL = "neighbourhood";
