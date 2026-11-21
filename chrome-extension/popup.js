const DEFAULT_API_URL = "http://localhost:8000/api";

const apiUrlInput = document.getElementById("api-url");
const saveApiUrlButton = document.getElementById("save-api-url");
const analyzeTabButton = document.getElementById("analyze-tab");
const statusElement = document.getElementById("status");
const resultSection = document.getElementById("result");
const sourceElement = document.getElementById("source");
const verdictElement = document.getElementById("verdict");
const confidenceElement = document.getElementById("confidence");
const redFlagsElement = document.getElementById("red-flags");
const explanationElement = document.getElementById("explanation");

function normalizeApiBase(value) {
  const parsed = new URL(value.trim());
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("The API URL must use HTTP or HTTPS.");
  }
  if (parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error("Enter an API base URL without credentials, query parameters, or a fragment.");
  }
  return parsed.href.replace(/\/+$/, "");
}

function permissionPattern(apiBaseUrl) {
  const parsed = new URL(apiBaseUrl);
  return `${parsed.protocol}//${parsed.hostname}/*`;
}

function showStatus(message, isError = false) {
  statusElement.textContent = message;
  statusElement.classList.toggle("error", isError);
}

function renderResult(record) {
  if (!record) {
    resultSection.hidden = true;
    return;
  }
  resultSection.hidden = false;
  sourceElement.textContent = `Source: ${record.source || "Scam Shield"}`;
  redFlagsElement.replaceChildren();

  if (record.error) {
    verdictElement.textContent = "Scan unavailable";
    verdictElement.className = "verdict";
    confidenceElement.textContent = "";
    explanationElement.textContent = record.error;
    return;
  }

  const data = record.data || {};
  const label = String(data.label || "unknown");
  const isScam = !["benign", "unknown"].includes(label.toLowerCase());
  verdictElement.textContent = label.replace(/[_-]+/g, " ");
  verdictElement.className = `verdict ${isScam ? "scam" : "legitimate"}`;

  const confidence = typeof data.confidence === "number" && Number.isFinite(data.confidence)
    ? data.confidence
    : Number(data.probs?.[label.toLowerCase()]);
  confidenceElement.textContent = Number.isFinite(confidence)
    ? `Confidence: ${(confidence * 100).toFixed(1)}%`
    : "Confidence unavailable";

  const flags = Array.isArray(data.red_flags) ? data.red_flags : [];
  if (flags.length === 0) {
    const item = document.createElement("li");
    item.textContent = "No structured red flags identified.";
    redFlagsElement.append(item);
  } else {
    for (const flag of flags) {
      const item = document.createElement("li");
      const severity = flag.severity ? ` (${String(flag.severity).toUpperCase()})` : "";
      const evidence = flag.evidence ? ` — ${String(flag.evidence)}` : "";
      item.textContent = `${String(flag.label || flag.code || "Red flag")}${severity}${evidence}`;
      redFlagsElement.append(item);
    }
  }
  explanationElement.textContent = String(data.explanation || "No explanation was returned.");
}

async function requestApiPermission(apiBaseUrl) {
  const granted = await chrome.permissions.request({
    origins: [permissionPattern(apiBaseUrl)],
  });
  if (!granted) {
    throw new Error("Permission to contact this API host was not granted.");
  }
}

async function runAnalysis(kind, content, source, preauthorizedApiBaseUrl) {
  if (!content || !content.trim()) {
    throw new Error("There is no text or URL to scan.");
  }
  const apiBaseUrl = normalizeApiBase(preauthorizedApiBaseUrl || apiUrlInput.value || DEFAULT_API_URL);
  if (!preauthorizedApiBaseUrl) {
    await requestApiPermission(apiBaseUrl);
  }
  await chrome.storage.local.set({ apiBaseUrl });
  showStatus("Scanning…");
  const response = await chrome.runtime.sendMessage({
    type: "ANALYZE",
    kind,
    content,
    source,
    apiBaseUrl,
  });
  if (!response?.ok) {
    throw new Error(response?.error || "The scan could not be completed.");
  }
  renderResult(response.record);
  showStatus("Scan complete.");
}

saveApiUrlButton.addEventListener("click", async () => {
  try {
    const apiBaseUrl = normalizeApiBase(apiUrlInput.value || DEFAULT_API_URL);
    await requestApiPermission(apiBaseUrl);
    await chrome.storage.local.set({ apiBaseUrl });
    apiUrlInput.value = apiBaseUrl;
    showStatus("API URL saved and host access granted.");
  } catch (error) {
    showStatus(error.message || "Could not save the API URL.", true);
  }
});

analyzeTabButton.addEventListener("click", async () => {
  analyzeTabButton.disabled = true;
  try {
    const apiBaseUrl = normalizeApiBase(apiUrlInput.value || DEFAULT_API_URL);
    await requestApiPermission(apiBaseUrl);
    const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!activeTab?.url || !/^https?:\/\//i.test(activeTab.url)) {
      throw new Error("The active tab does not have a scannable HTTP or HTTPS URL.");
    }
    await runAnalysis("url", activeTab.url, "active tab URL", apiBaseUrl);
  } catch (error) {
    showStatus(error.message || "Could not scan the active tab.", true);
  } finally {
    analyzeTabButton.disabled = false;
  }
});

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName === "local" && changes.lastAnalysis) {
    renderResult(changes.lastAnalysis.newValue);
  }
});

chrome.storage.local.get(["apiBaseUrl", "lastAnalysis"]).then((stored) => {
  apiUrlInput.value = stored.apiBaseUrl || DEFAULT_API_URL;
  renderResult(stored.lastAnalysis);
});
