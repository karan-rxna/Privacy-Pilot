// PrivacyPilot - storage layer (ES module, imported by background.js).
//
// The original addEvent did an unserialised read-modify-write, so two events
// arriving close together would clobber each other. Every write now goes
// through a single promise chain, and history is capped so chrome.storage.local
// does not grow without bound.

const MAX_EVENTS = 1000;

export const DEFAULT_SETTINGS = {
  blocking: true,
  blurLocation: false,
  blurRadiusMeters: 1000
};

// Serialises all read-modify-write operations.
let writeQueue = Promise.resolve();

function enqueue(task) {
  const run = writeQueue.then(task, task);
  // Keep the chain alive even if one task rejects.
  writeQueue = run.catch(() => {});
  return run;
}

function get(keys) {
  return new Promise((resolve) => {
    chrome.storage.local.get(keys, (data) => {
      void chrome.runtime.lastError;
      resolve(data || {});
    });
  });
}

function set(items) {
  return new Promise((resolve) => {
    chrome.storage.local.set(items, () => {
      void chrome.runtime.lastError;
      resolve();
    });
  });
}

export const Storage = {
  async getEvents() {
    const data = await get(["events"]);
    return Array.isArray(data.events) ? data.events : [];
  },

  async getEventsForSite(site) {
    const events = await this.getEvents();
    return events.filter((e) => e.site === site);
  },

  addEvent(event) {
    return enqueue(async () => {
      const events = await Storage.getEvents();

      // Collapse repeats: same site + type within a minute is one event.
      const last = events[events.length - 1];
      if (
        last &&
        last.site === event.site &&
        last.type === event.type &&
        event.timestamp - last.timestamp < 60000
      ) {
        last.count = (last.count || 1) + 1;
        last.timestamp = event.timestamp;
      } else {
        events.push({ ...event, count: 1 });
      }

      if (events.length > MAX_EVENTS) {
        events.splice(0, events.length - MAX_EVENTS);
      }
      await set({ events });
      return events;
    });
  },

  clearEvents() {
    return enqueue(() => set({ events: [], phishing: {} }));
  },

  async getSettings() {
    const data = await get(["settings"]);
    return { ...DEFAULT_SETTINGS, ...(data.settings || {}) };
  },

  setSettings(patch) {
    return enqueue(async () => {
      const current = await Storage.getSettings();
      const settings = { ...current, ...patch };
      await set({ settings });
      return settings;
    });
  },

  async getPhishing(site) {
    const data = await get(["phishing"]);
    const all = data.phishing || {};
    return site ? all[site] || null : all;
  },

  setPhishing(site, findings) {
    return enqueue(async () => {
      const data = await get(["phishing"]);
      const all = data.phishing || {};
      if (findings && findings.length) {
        all[site] = { findings, timestamp: Date.now() };
      } else {
        delete all[site];
      }
      // Keep this bounded too.
      const keys = Object.keys(all);
      if (keys.length > 200) {
        keys
          .sort((a, b) => (all[a].timestamp || 0) - (all[b].timestamp || 0))
          .slice(0, keys.length - 200)
          .forEach((k) => delete all[k]);
      }
      await set({ phishing: all });
    });
  }
};
