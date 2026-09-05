/**
 * PrivacyPilot AI — MAIN world observer.
 *
 * Runs at document_start in the page's own JS realm, before site code executes.
 * It wraps the browser APIs that trigger permission prompts or leak entropy, so we
 * can see the *call* (and which script made it) rather than the prompt, which
 * extensions cannot observe.
 *
 * Non-negotiable: this must never change page behaviour. Every wrapper calls
 * through to the original, and every report is wrapped in try/catch.
 */
(() => {
  "use strict";

  const CHANNEL = "__privacypilot__";
  const seen = new Map();
  const RATE_LIMIT_MS = 1500;

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

  function report(kind, api, detail) {
    try {
      const key = kind + api + (detail || "");
      const now = Date.now();
      if (seen.has(key) && now - seen.get(key) < RATE_LIMIT_MS) return;
      seen.set(key, now);

      window.postMessage(
        {
          source: CHANNEL,
          kind,
          api,
          detail: detail || null,
          origin: location.origin,
          frame: window.top === window ? "top" : "iframe",
          script: callerScript(),
          at: now
        },
        location.origin === "null" ? "*" : location.origin
      );
    } catch {}
  }

  function wrap(target, name, kind, describe) {
    try {
      if (!target || typeof target[name] !== "function") return;
      const original = target[name];
      const replacement = function (...args) {
        try {
          report(kind, name, describe ? describe(args) : null);
        } catch {}
        return original.apply(this, args);
      };
      Object.defineProperty(replacement, "name", { value: name });
      Object.defineProperty(replacement, "toString", {
        value: () => original.toString(),
        configurable: true
      });
      target[name] = replacement;
    } catch {}
  }

  /* ---- Permission-gated APIs ---- */

  if (navigator.mediaDevices) {
    wrap(navigator.mediaDevices, "getUserMedia", "permission", (args) => {
      const c = args[0] || {};
      const wants = [];
      if (c.audio) wants.push("microphone");
      if (c.video) wants.push("camera");
      return wants.join(" + ") || "media";
    });
    wrap(navigator.mediaDevices, "getDisplayMedia", "permission", () => "screen capture");
    wrap(navigator.mediaDevices, "enumerateDevices", "probe", () => "device list");
  }

  if (navigator.geolocation) {
    wrap(navigator.geolocation, "getCurrentPosition", "permission", (args) => {
      const opts = args[2] || {};
      return opts.enableHighAccuracy ? "location (high accuracy)" : "location";
    });
    wrap(navigator.geolocation, "watchPosition", "permission", () => "location (continuous)");
  }

  if (window.Notification) {
    wrap(Notification, "requestPermission", "permission", () => "notifications");
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
  if (navigator.mediaSession) report("probe", "mediaSession", "media session available");

  /* ---- Fingerprinting surfaces ---- */

  if (window.HTMLCanvasElement) {
    wrap(HTMLCanvasElement.prototype, "toDataURL", "fingerprint", () => "canvas readback");
    wrap(HTMLCanvasElement.prototype, "toBlob", "fingerprint", () => "canvas readback");
  }
  if (window.CanvasRenderingContext2D) {
    wrap(CanvasRenderingContext2D.prototype, "getImageData", "fingerprint", () => "canvas pixels");
    wrap(CanvasRenderingContext2D.prototype, "measureText", "fingerprint", () => "font metrics");
  }

  for (const ctx of ["WebGLRenderingContext", "WebGL2RenderingContext"]) {
    if (window[ctx]) {
      try {
        const proto = window[ctx].prototype;
        const original = proto.getParameter;
        proto.getParameter = function (param) {
          try {
            // UNMASKED_RENDERER_WEBGL / UNMASKED_VENDOR_WEBGL
            if (param === 37446 || param === 37445) {
              report("fingerprint", "getParameter", "GPU model");
            }
          } catch {}
          return original.apply(this, arguments);
        };
      } catch {}
    }
  }

  if (window.AudioContext || window.webkitAudioContext) {
    const AC = window.AudioContext || window.webkitAudioContext;
    wrap(AC.prototype, "createOscillator", "fingerprint", () => "audio stack");
    wrap(AC.prototype, "createAnalyser", "fingerprint", () => "audio stack");
  }

  if (navigator.mediaDevices || navigator.plugins) {
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
  }
})();
