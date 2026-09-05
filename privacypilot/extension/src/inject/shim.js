/**
 * PrivacyPilot AI — MAIN world observer and interceptor.
 *
 * Runs at document_start in the page's own JS realm, before site code executes.
 * It wraps the browser APIs that trigger permission prompts or leak entropy, so
 * we can see the *call* (and which script made it) rather than the prompt, which
 * extensions cannot observe.
 *
 * It does three things, in increasing order of intrusiveness:
 *
 *   1. OBSERVE  — log the call, the time, the frame, and the calling script
 *   2. DEFER    — hold the call while PrivacyPilot asks the user
 *   3. DEGRADE  — let the call succeed, but answer with less than the truth
 *
 * Non-negotiable: this must never break the page. Every wrapper calls through to
 * the original, every report is wrapped in try/catch, and every deferred promise
 * has a timeout that fails OPEN. An extension that silently breaks every website
 * is worse than one that occasionally stops protecting.
 */
(() => {
  "use strict";

  const CHANNEL = "__privacypilot__";
  const seen = new Map();
  const RATE_LIMIT_MS = 1500;

  /* ------------------------------------------------------------------ */
  /* Reporting                                                           */
  /* ------------------------------------------------------------------ */

  function callerScript() {
    try {
      const lines = new Error().stack.split("\n").slice(3);
      for (const line of lines) {
        const match = line.match(/https?:\/\/[^\s)]+/);
        if (match && !match[0].includes("chrome-extension://")) {
          return match[0].split("?")[0];
        }
      }
    } catch {}
    return "inline script";
  }

  function post(payload) {
    try {
      window.postMessage(
        { source: CHANNEL, ...payload },
        location.origin === "null" ? "*" : location.origin
      );
    } catch {}
  }

  function report(kind, api, detail) {
    try {
      const key = kind + api + (detail || "");
      const now = Date.now();
      // Some sites poll geolocation. Without this they flood the feed.
      if (seen.has(key) && now - seen.get(key) < RATE_LIMIT_MS) return;
      seen.set(key, now);

      post({
        kind,
        api,
        detail: detail || null,
        origin: location.origin,
        frame: window.top === window ? "top" : "iframe",
        script: callerScript(),
        at: now
      });
    } catch {}
  }

  /* ------------------------------------------------------------------ */
  /* Deferred consent                                                    */
  /* ------------------------------------------------------------------ */

  /**
   * Notification.requestPermission is deliberately absent. It requires transient
   * user activation, which expires in a few seconds — by the time an async
   * dialog returns a decision the activation is gone and the call fails. Do not
   * "fix" this by adding it.
   */
  const DEFERRABLE = new Set([
    "microphone", "camera", "screen capture",
    "location", "location (high accuracy)", "location (continuous)",
    "clipboard read", "bluetooth", "usb device"
  ]);

  const DECISION_TIMEOUT_MS = 8000;

  let requestSeq = 0;
  const pending = new Map();

  function askPrivacyPilot(detail, api, script) {
    if (!DEFERRABLE.has(detail)) return Promise.resolve("allow");

    return new Promise((resolve) => {
      const id = ++requestSeq;
      // Fail open. A promise that never settles hangs the page forever.
      const timer = setTimeout(() => {
        pending.delete(id);
        resolve("allow");
      }, DECISION_TIMEOUT_MS);

      pending.set(id, { resolve, timer });

      try {
        post({ kind: "ask", id, api, detail, script, at: Date.now() });
      } catch {
        clearTimeout(timer);
        pending.delete(id);
        resolve("allow");
      }
    });
  }

  /* ------------------------------------------------------------------ */
  /* Fuzzing — copied verbatim from lib/fuzzing.js                       */
  /*                                                                     */
  /* The shim cannot import ES modules. If you change one, change both.  */
  /*                                                                     */
  /* The distortion is DETERMINISTIC PER ORIGIN, never random per call.  */
  /* Fresh noise on every call would let a site call the API twenty times */
  /* and average it away — random noise is a delay, not privacy.         */
  /* ------------------------------------------------------------------ */

  /**
   * The config arrives from the bridge on a round trip through the service
   * worker, which is asynchronous — but plenty of sites fingerprint during
   * initial parse, before it lands. So the defaults here are what protects that
   * window, and they must match lib/fuzzing.js (DEFAULT_MODE = "approximate"),
   * not fall back to passing the true values through.
   *
   * The bootstrap seed is derived from the origin alone, with the same "pp"
   * fallback salt the worker uses when no per-install salt exists yet. It is
   * replaced by the salted seed as soon as the config arrives.
   */
  function hashString(str) {
    let h = 0x811c9dc5;
    for (let i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = Math.imul(h, 0x01000193);
    }
    return h >>> 0;
  }

  let fuzzSeed = hashString(`pp::${location.origin}`);
  let fuzzMode = "approximate";
  let fuzzLevel = "neighbourhood";

  function rngFrom(seed) {
    let a = seed >>> 0;
    return function () {
      a = (a + 0x6d2b79f5) >>> 0;
      let t = a;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  const LOCATION_GRIDS = {
    precise: null, street: 0.001, neighbourhood: 0.01, city: 0.05, region: 0.25
  };

  function fuzzPosition(position, seed, level) {
    const grid = LOCATION_GRIDS[level];
    if (!grid) return position;
    const rand = rngFrom(seed);
    const c = position.coords;
    // Snap to a grid rather than adding an offset: an offset still encodes the
    // true position plus a constant, while a grid destroys the information.
    const snap = (v, o) => Math.round(v / grid) * grid + (o - 0.5) * grid * 0.4;
    return {
      coords: {
        latitude: Number(snap(c.latitude, rand()).toFixed(6)),
        longitude: Number(snap(c.longitude, rand()).toFixed(6)),
        // Accuracy MUST widen to match the grid. Reporting 20 m accuracy on a
        // coordinate 5 km off is the contradiction that betrays a spoofer.
        accuracy: Math.max(c.accuracy || 0, grid * 111000 * 0.5),
        altitude: null, altitudeAccuracy: null, heading: null, speed: null
      },
      timestamp: position.timestamp
    };
  }

  function perturbPixels(data, seed, samples) {
    if (!data || !data.length) return data;
    const rand = rngFrom(seed);
    const pixels = data.length / 4;
    const n = samples || 240;
    for (let i = 0; i < n; i++) {
      const idx = Math.floor(rand() * pixels) * 4 + Math.floor(rand() * 3);
      const next = data[idx] + (rand() < 0.5 ? -1 : 1);
      if (next >= 0 && next <= 255) data[idx] = next;
    }
    return data;
  }

  // Blending into a crowd beats being unique, so these are ordinary values.
  const COMMON_RENDERERS = [
    "ANGLE (Intel, Intel(R) UHD Graphics (0x00009A49) Direct3D11 vs_5_0 ps_5_0, D3D11)",
    "ANGLE (Intel, Intel(R) HD Graphics 620 Direct3D11 vs_5_0 ps_5_0, D3D11)",
    "ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 Direct3D11 vs_5_0 ps_5_0, D3D11)",
    "ANGLE (AMD, AMD Radeon(TM) Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)"
  ];

  /* ------------------------------------------------------------------ */
  /* Inbound messages from the bridge                                    */
  /* ------------------------------------------------------------------ */

  window.addEventListener("message", (event) => {
    if (event.source !== window) return;
    const d = event.data;
    if (!d) return;

    if (d.source === CHANNEL + ":decision") {
      const entry = pending.get(d.id);
      if (!entry) return;
      clearTimeout(entry.timer);
      pending.delete(d.id);
      entry.resolve(d.verdict === "deny" ? "deny" : "allow");
      return;
    }

    if (d.source === CHANNEL + ":config") {
      // >>> 0, not | 0. seedFor returns an unsigned 32-bit hash; | 0 makes the
      // top half of that range negative, and a negative index into
      // COMMON_RENDERERS returns undefined — which would report a GPU of
      // "undefined" and make the user uniquely identifiable, the exact opposite
      // of the intent. It also keeps the index identical to
      // lib/fuzzing.js#genericRenderer.
      fuzzSeed = (d.seed || 0) >>> 0;
      fuzzMode = d.mode || "approximate";
      fuzzLevel = d.locationLevel || "neighbourhood";
    }
  });

  /* ------------------------------------------------------------------ */
  /* Generic wrapper                                                     */
  /* ------------------------------------------------------------------ */

  function wrap(target, name, kind, describe) {
    try {
      if (!target || typeof target[name] !== "function") return;
      const original = target[name];

      // Deliberately NOT an async function. An async wrapper returns a promise
      // for every call. That is invisible on an API which is already async, but
      // it breaks any synchronous one — createOscillator() handing back a
      // promise instead of an OscillatorNode kills the page's audio outright.
      //
      // Invariant: every API wrapped as "permission" is itself promise-returning
      // (getUserMedia, clipboard, storage.persist, bluetooth, usb), so only that
      // branch returns a promise. Do not wrap a synchronous API as "permission"
      // without revisiting this.
      const replacement = function (...args) {
        const detail = describe ? describe(args) : null;
        const script = callerScript();
        try { report(kind, name, detail); } catch {}

        if (kind !== "permission" || !detail) return original.apply(this, args);

        const self = this;
        return askPrivacyPilot(detail, name, script).then((verdict) => {
          if (verdict === "deny" || fuzzMode === "denied") {
            // The exact error Chrome throws on a real denial, so the site's own
            // error handling runs and it cannot detect the extension.
            throw new DOMException("Permission denied", "NotAllowedError");
          }
          return original.apply(self, args);
        });
      };

      Object.defineProperty(replacement, "name", { value: name });
      Object.defineProperty(replacement, "toString", {
        value: () => original.toString(),
        configurable: true
      });
      target[name] = replacement;
    } catch {}
  }

  /* ------------------------------------------------------------------ */
  /* Permission-gated APIs                                               */
  /* ------------------------------------------------------------------ */

  if (navigator.mediaDevices) {
    wrap(navigator.mediaDevices, "getUserMedia", "permission", (args) => {
      const c = args[0] || {};
      const wants = [];
      if (c.audio) wants.push("microphone");
      if (c.video) wants.push("camera");
      return wants[0] || "microphone";
    });
    wrap(navigator.mediaDevices, "getDisplayMedia", "permission", () => "screen capture");
    wrap(navigator.mediaDevices, "enumerateDevices", "probe", () => "device list");
  }

  if (navigator.clipboard) {
    wrap(navigator.clipboard, "readText", "permission", () => "clipboard read");
    wrap(navigator.clipboard, "read", "permission", () => "clipboard read");
    wrap(navigator.clipboard, "writeText", "probe", () => "clipboard write");
  }

  if (navigator.storage) {
    wrap(navigator.storage, "persist", "permission", () => "persistent storage");
  }

  if (navigator.permissions) {
    wrap(navigator.permissions, "query", "probe", (args) => {
      const d = args[0] || {};
      return d.name ? `permission state: ${d.name}` : "permission state";
    });
  }

  if (navigator.bluetooth) wrap(navigator.bluetooth, "requestDevice", "permission", () => "bluetooth");
  if (navigator.usb) wrap(navigator.usb, "requestDevice", "permission", () => "usb device");

  // Not deferred: requestPermission needs transient user activation, which
  // expires before an async dialog can return. Observed only.
  if (window.Notification) {
    try {
      const origNotify = Notification.requestPermission;
      Notification.requestPermission = function (...args) {
        report("permission", "requestPermission", "notifications");
        return origNotify.apply(this, args);
      };
    } catch {}
  }

  /* ------------------------------------------------------------------ */
  /* Geolocation — callback-based, so it needs its own handling          */
  /* ------------------------------------------------------------------ */

  if (navigator.geolocation) {
    const origGet = navigator.geolocation.getCurrentPosition.bind(navigator.geolocation);
    const origWatch = navigator.geolocation.watchPosition.bind(navigator.geolocation);

    const geoDetail = (opts, continuous) =>
      continuous ? "location (continuous)"
        : (opts && opts.enableHighAccuracy) ? "location (high accuracy)" : "location";

    function denied(err) {
      if (typeof err !== "function") return;
      err({
        code: 1, message: "User denied Geolocation",
        PERMISSION_DENIED: 1, POSITION_UNAVAILABLE: 2, TIMEOUT: 3
      });
    }

    const maybeFuzz = (position) =>
      fuzzMode === "approximate" ? fuzzPosition(position, fuzzSeed, fuzzLevel) : position;

    navigator.geolocation.getCurrentPosition = function (ok, err, opts) {
      const detail = geoDetail(opts, false);
      report("permission", "getCurrentPosition", detail);

      askPrivacyPilot(detail, "getCurrentPosition", callerScript()).then((verdict) => {
        if (verdict === "deny" || fuzzMode === "denied") return denied(err);
        origGet((position) => {
          if (typeof ok === "function") ok(maybeFuzz(position));
        }, err, opts);
      });
    };

    navigator.geolocation.watchPosition = function (ok, err, opts) {
      const detail = geoDetail(opts, true);
      report("permission", "watchPosition", detail);

      // watchPosition must return an id synchronously, so we cannot await the
      // decision. Start the watch and gate each callback instead.
      let allowed = null;
      askPrivacyPilot(detail, "watchPosition", callerScript()).then((verdict) => {
        allowed = verdict !== "deny" && fuzzMode !== "denied";
        if (!allowed) denied(err);
      });

      return origWatch((position) => {
        if (allowed !== true || typeof ok !== "function") return;
        ok(maybeFuzz(position));
      }, err, opts);
    };
  }

  /* ------------------------------------------------------------------ */
  /* Fingerprinting surfaces                                             */
  /*                                                                     */
  /* These are degraded rather than blocked. Real features use canvas —  */
  /* charts, image editors, PDF rendering — so blocking breaks pages. A  */
  /* one-step change in a few hundred pixels is invisible to the eye but */
  /* changes the fingerprint hash completely.                            */
  /* ------------------------------------------------------------------ */

  let origGetImageData = null;

  if (window.CanvasRenderingContext2D) {
    try {
      origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
      CanvasRenderingContext2D.prototype.getImageData = function (...args) {
        report("fingerprint", "getImageData", "canvas pixels");
        const result = origGetImageData.apply(this, args);
        if (fuzzMode === "approximate" && result && result.data) {
          perturbPixels(result.data, fuzzSeed);
        }
        return result;
      };

      const origMeasure = CanvasRenderingContext2D.prototype.measureText;
      CanvasRenderingContext2D.prototype.measureText = function (...args) {
        report("fingerprint", "measureText", "font metrics");
        return origMeasure.apply(this, args);
      };
    } catch {}
  }

  if (window.HTMLCanvasElement) {
    try {
      const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
      const origToBlob = HTMLCanvasElement.prototype.toBlob;

      /**
       * Return a perturbed *copy* of a canvas, or null if we should not touch
       * this call.
       *
       * Perturbing the canvas in place and writing it back with putImageData
       * looks equivalent and is not: the next readback re-perturbs pixels that
       * were already perturbed, so the value drifts by one more step on every
       * call. That breaks the guarantee this whole module exists for — a site
       * that reads the canvas twenty times could average the drift away and
       * recover the true fingerprint — and it visibly degrades the user's own
       * canvas, which we have no right to modify.
       *
       * Working on a copy keeps every readback of the same pixels identical,
       * because the same seed produces the same perturbation from the same
       * source, however many times it runs.
       */
      function fuzzedCopy(canvas) {
        if (fuzzMode !== "approximate" || !origGetImageData) return null;
        if (!canvas.width || !canvas.height) return null;
        try {
          const copy = document.createElement("canvas");
          copy.width = canvas.width;
          copy.height = canvas.height;
          const ctx = copy.getContext("2d");
          if (!ctx) return null;
          ctx.drawImage(canvas, 0, 0);
          const img = origGetImageData.call(ctx, 0, 0, copy.width, copy.height);
          perturbPixels(img.data, fuzzSeed);
          ctx.putImageData(img, 0, 0);
          return copy;
        } catch {
          // Tainted by a cross-origin image, out of memory, whatever. Fall back
          // to the real call so the page sees the behaviour it expects —
          // including the SecurityError it was already going to get.
          return null;
        }
      }

      HTMLCanvasElement.prototype.toDataURL = function (...args) {
        report("fingerprint", "toDataURL", "canvas readback");
        const copy = fuzzedCopy(this);
        return origToDataURL.apply(copy || this, args);
      };

      // toBlob is the same readback by another name. Leaving it unfuzzed left
      // an open path to the true canvas fingerprint.
      HTMLCanvasElement.prototype.toBlob = function (...args) {
        report("fingerprint", "toBlob", "canvas readback");
        const copy = fuzzedCopy(this);
        return origToBlob.apply(copy || this, args);
      };
    } catch {}
  }

  for (const ctxName of ["WebGLRenderingContext", "WebGL2RenderingContext"]) {
    if (!window[ctxName]) continue;
    try {
      const proto = window[ctxName].prototype;
      const origGetParameter = proto.getParameter;
      proto.getParameter = function (param) {
        // UNMASKED_RENDERER_WEBGL / UNMASKED_VENDOR_WEBGL
        if (param === 37446 || param === 37445) {
          report("fingerprint", "getParameter", "GPU model");
          if (fuzzMode === "approximate") {
            return param === 37446
              ? COMMON_RENDERERS[fuzzSeed % COMMON_RENDERERS.length]
              : "Google Inc. (Intel)";
          }
        }
        return origGetParameter.apply(this, arguments);
      };
    } catch {}
  }

  if (window.AudioContext || window.webkitAudioContext) {
    const AC = window.AudioContext || window.webkitAudioContext;
    wrap(AC.prototype, "createOscillator", "fingerprint", () => "audio stack");
    wrap(AC.prototype, "createAnalyser", "fingerprint", () => "audio stack");
  }

  try {
    const plugins = Object.getOwnPropertyDescriptor(Navigator.prototype, "plugins");
    if (plugins && plugins.get) {
      Object.defineProperty(Navigator.prototype, "plugins", {
        configurable: true,
        get: function () {
          report("fingerprint", "plugins", "plugin enumeration");
          return plugins.get.call(this);
        }
      });
    }
  } catch {}
})();
