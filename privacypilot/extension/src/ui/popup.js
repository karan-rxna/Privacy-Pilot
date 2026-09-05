import { CATEGORIES } from "../lib/trackers.js";
import { MODES, LOCATION_GRIDS } from "../lib/fuzzing.js";

const $ = (id) => document.getElementById(id);
const CIRCUMFERENCE = 2 * Math.PI * 33;
const EMPTY_DASH = "—";
let currentTabId = null;
let currentOrigin = null;
let currentMode = null;
/** True once the user has changed the mode, so we can ask for a reload. */
let modeChanged = false;

document.body.classList.add("popup-ready");

function scoreColor(score) {
  if (score >= 80) return "var(--low)";
  if (score >= 60) return "var(--medium)";
  return "var(--high)";
}

function animateScore(nextScore) {
  const node = $("scoreVal");
  const previousScore = Number(node.dataset.score || 0);
  if (previousScore === nextScore) return;

  const startedAt = performance.now();
  const duration = 650;
  const tick = (now) => {
    const progress = Math.min(1, (now - startedAt) / duration);
    const easedProgress = 1 - Math.pow(1 - progress, 3);
    node.textContent = Math.round(previousScore + (nextScore - previousScore) * easedProgress);
    if (progress < 1) requestAnimationFrame(tick);
  };

  node.dataset.score = String(nextScore);
  requestAnimationFrame(tick);
}

function formatTime(timestamp) {
  const date = new Date(timestamp);
  return `${String(date.getMinutes()).padStart(2, "0")}:${String(date.getSeconds()).padStart(2, "0")}`;
}

function getHostname(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return EMPTY_DASH;
  }
}

function getScriptName(script) {
  if (!script || script === "inline script") return script;
  try {
    return new URL(script, "http://x").pathname.split("/").pop() || script;
  } catch {
    return script;
  }
}

function renderActivity(events) {
  $("feedCount").textContent = events.length;
  if (!events.length) {
    $("feed").innerHTML = `<p class="empty">No permission or fingerprinting calls yet.</p>`;
    return;
  }

  $("feed").innerHTML = events.slice().reverse().slice(0, 24).map((event) => {
    const color = event.kind === "permission" ? "var(--high)"
      : event.kind === "fingerprint" ? "var(--medium)" : "var(--ink-dim)";
    const source = getScriptName(event.script);
    const iframePrefix = event.frame === "iframe" ? "iframe · " : "";

    return `
      <div class="feed-row">
        <span class="t">${formatTime(event.at)}</span>
        <span class="api" style="color:${color}">
          ${event.detail || event.api}<span class="src">${iframePrefix}${source || ""}</span>
        </span>
        <span class="t">${event.kind}</span>
      </div>`;
  }).join("");
}

function renderPermissions(permissions) {
  $("perms").innerHTML = permissions.length
    ? permissions.map((permission) => `
        <div class="kv">
          <span>${permission.label}${permission.plausible ? "" : " · not typical here"}</span>
          <span class="pill ${permission.level}">${permission.level}</span>
        </div>`).join("")
    : `<p class="empty">None observed.</p>`;
}

function renderTrackers(trackers) {
  const groups = {};
  for (const tracker of trackers) (groups[tracker.category] ||= []).push(tracker.name);

  $("trackerCount").textContent = trackers.length;
  $("trackers").innerHTML = Object.keys(groups).length
    ? Object.entries(groups).map(([category, names]) => `
        <div class="kv">
          <span style="color:${CATEGORIES[category]?.color || "var(--ink)"}">${CATEGORIES[category]?.label || category}</span>
          <span>${[...new Set(names)].join(", ")}</span>
        </div>`).join("")
    : `<p class="empty">None detected.</p>`;
}

function renderBreakdown(breakdown) {
  $("breakdown").innerHTML = breakdown.length
    ? breakdown.map((item) => `
        <div class="kv" style="display:block">
          <div style="display:flex;justify-content:space-between">
            <span>${item.label}${item.count != null ? ` (${item.count})` : ""}</span>
            <span>−${item.cost}</span>
          </div>
          <div class="bar"><i style="width:${Math.min(100, item.cost * 2.5)}%"></i></div>
        </div>`).join("")
    : `<p class="empty">Nothing deducted.</p>`;
}

function renderRecommendations(recommendations) {
  $("recs").innerHTML = recommendations.map((recommendation) => `
    <div class="rec">
      <strong>${recommendation.title}</strong>
      <p>${recommendation.body}</p>
    </div>`).join("");
}

function renderPolicy(analysis) {
  const sections = [
    ["Data collected", analysis.dataCollected],
    ["Shared with", analysis.dataShared],
    ["Retention", analysis.retention],
    ["Advertising use", analysis.advertising],
    ["Your controls", analysis.userControls]
  ];

  $("policyBody").innerHTML = `
    <div class="kv"><span>Policy readability</span><span>${analysis.readability || EMPTY_DASH}</span></div>
    ${sections.map(([title, detail]) => `
      <div class="rec"><strong>${title}</strong><p>${detail || "Not stated"}</p></div>`).join("")}
    ${(analysis.risks || []).map((risk) => `<div class="rec"><strong style="color:var(--high)">${risk}</strong></div>`).join("")}
    <p class="empty" style="margin-top:8px">Summary generated by a language model. The score above is computed from observed behaviour, not from this text.</p>`;
}

/**
 * The per-site mode switch.
 *
 * This is not a nicety. "Approximate" is the default and it genuinely breaks
 * things — a delivery site handed a position 1 km out shows the wrong shops —
 * and silent breakage is exactly how people come to uninstall a privacy tool.
 * The escape hatch has to be one click away, and the current state has to be
 * visible without hunting for it.
 */
function renderModes(fuzz) {
  const mode = MODES[fuzz?.mode] ? fuzz.mode : "approximate";
  const level = LOCATION_GRIDS[fuzz?.level] !== undefined ? fuzz.level : "neighbourhood";
  const container = $("modes");

  $("fuzzScope").textContent = mode === "approximate" ? level : EMPTY_DASH;

  if (currentMode !== mode) {
    currentMode = mode;
    container.innerHTML = Object.values(MODES).map((entry) => `
      <button type="button" data-mode="${entry.id}"
              aria-pressed="${entry.id === mode}">${entry.label}</button>`).join("");

    container.querySelectorAll("[data-mode]").forEach((button) =>
      button.addEventListener("click", () => setMode(button.dataset.mode))
    );
  }

  $("modeDetail").innerHTML =
    `<b>${MODES[mode].label}</b>${MODES[mode].detail}`;
  $("modeNote").hidden = !modeChanged;
}

async function setMode(mode) {
  if (!currentOrigin || mode === currentMode) return;
  const response = await chrome.runtime.sendMessage({
    type: "PP_SET_FUZZ_MODE",
    origin: currentOrigin,
    mode
  });
  if (!response?.ok) return;

  modeChanged = true;
  currentMode = null; // force a repaint of the button row
  renderModes({ mode: response.mode, level: response.level });
}

function render({ url, origin, state, result, fuzz }) {
  $("host").textContent = getHostname(url);
  animateScore(result.score);
  $("scoreVal").style.color = scoreColor(result.score);

  const arc = $("arc");
  arc.style.stroke = scoreColor(result.score);
  arc.style.transition = "stroke-dashoffset 600ms cubic-bezier(0.2, 0.8, 0.2, 1)";
  arc.setAttribute("stroke-dashoffset", CIRCUMFERENCE * (1 - result.score / 100));

  $("band").textContent = result.band;
  $("subline").textContent = `Site type read as "${result.siteType}" · ${state.trackers.length} trackers · ${result.permissions.length} permissions`;

  renderActivity(state.events || []);
  renderPermissions(result.permissions);
  renderTrackers(state.trackers);
  renderBreakdown(result.breakdown);
  renderRecommendations(result.recommendations);
  renderModes(fuzz);
  if (state.policySummary) renderPolicy(state.policySummary);
}

async function load() {
  const response = await chrome.runtime.sendMessage({ type: "PP_GET_TAB" });
  if (!response || response.error) {
    $("band").textContent = "No page to analyse";
    $("subline").textContent = "Open a website and reopen this panel.";
    return;
  }
  currentTabId = response.tabId;
  currentOrigin = response.origin || null;
  render(response);
}

$("analyzeBtn").addEventListener("click", async () => {
  const button = $("analyzeBtn");
  button.disabled = true;
  button.textContent = "Reading policy…";
  $("policyBody").innerHTML = `<p class="empty">Fetching and summarising the policy…</p>`;

  try {
    const response = await chrome.runtime.sendMessage({ type: "PP_ANALYZE_POLICY", tabId: currentTabId });
    if (response.error) {
      $("policyBody").innerHTML = `<p class="err">${response.error}</p>`;
    } else {
      renderPolicy(response.analysis);
      await load();
    }
  } catch (error) {
    $("policyBody").innerHTML = `<p class="err">${error.message}</p>`;
  } finally {
    button.disabled = false;
    button.textContent = "Analyse policy";
  }
});

$("dashBtn").addEventListener("click", () => {
  const button = $("dashBtn");
  button.textContent = "Opening dashboard…";
  button.disabled = true;
  chrome.runtime.openOptionsPage();
});

load();
setInterval(load, 1200);
