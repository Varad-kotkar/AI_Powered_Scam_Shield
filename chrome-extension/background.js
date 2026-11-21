const DEFAULT_API_URL = "http://localhost:8000/api";
const MENU_ID = "scam-shield-scan";

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: MENU_ID,
      title: "Scan with Scam Shield",
      contexts: ["selection", "link", "page"],
    });
  });
});

function normalizeApiBase(value) {
  const parsed = new URL(value);
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("The configured API URL must use HTTP or HTTPS.");
  }
  if (parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error("The configured API base URL is invalid.");
  }
  return parsed.href.replace(/\/+$/, "");
}

async function saveError(source, error) {
  const record = {
    source,
    analyzedAt: new Date().toISOString(),
    error: error instanceof Error ? error.message : String(error),
  };
  await chrome.storage.local.set({ lastAnalysis: record });
  return record;
}

async function analyze({ kind, content, source, apiBaseUrl }) {
  try {
    if (!["text", "url"].includes(kind)) {
      throw new Error("Unsupported scan type.");
    }
    if (typeof content !== "string" || !content.trim()) {
      throw new Error("There is no text or URL to scan.");
    }
    if (content.length > 10000) {
      throw new Error("Selected content must be 10,000 characters or fewer.");
    }
    if (kind === "url") {
      const target = new URL(content);
      if (!["http:", "https:"].includes(target.protocol)) {
        throw new Error("Only HTTP and HTTPS links can be scanned.");
      }
    }
    const stored = await chrome.storage.local.get("apiBaseUrl");
    const baseUrl = normalizeApiBase(apiBaseUrl || stored.apiBaseUrl || DEFAULT_API_URL);
    const route = kind === "url" ? "url_check" : "text_check";
    const payload = kind === "url" ? { url: content } : { text: content };
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 25000);

    let response;
    try {
      response = await fetch(`${baseUrl}/${route}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timeoutId);
    }

    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = typeof data.detail === "string" ? data.detail : `Backend returned HTTP ${response.status}.`;
      throw new Error(detail);
    }

    const record = {
      source,
      analyzedAt: new Date().toISOString(),
      data,
    };
    await chrome.storage.local.set({ lastAnalysis: record });
    return record;
  } catch (error) {
    await saveError(source, error);
    throw error;
  }
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type !== "ANALYZE") return false;
  analyze(message)
    .then((record) => sendResponse({ ok: true, record }))
    .catch((error) => sendResponse({
      ok: false,
      error: error instanceof Error ? error.message : String(error),
    }));
  return true;
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  let kind;
  let content;
  let source;
  if (info.linkUrl) {
    kind = "url";
    content = info.linkUrl;
    source = "context-menu link";
  } else if (info.selectionText) {
    kind = "text";
    content = info.selectionText;
    source = "selected text";
  } else {
    kind = "url";
    content = info.pageUrl || tab?.url || "";
    source = "page URL";
  }
  analyze({ kind, content, source }).catch((error) => {
    console.error("Scam Shield context-menu scan failed:", error);
  });
});
