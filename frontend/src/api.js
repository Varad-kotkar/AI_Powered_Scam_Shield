import axios from "axios";

/**
 * @typedef {{
 *   item_id: string;
 *   index: number;
 *   input: string;
 *   kind: "text" | "url";
 *   label: string;
 *   confidence: number;
 *   probs: Record<string, number>;
 *   explanation: string;
 *   red_flags: Array<{ code: string; label: string; severity: string; evidence: string }>;
 *   allowlisted: boolean;
 *   allowlist_entry_id: string | null;
 *   feedback_submitted: boolean;
 *   error: string | null;
 * }} BatchScanResult
 */
/**
 * @typedef {{
 *   job_id: string;
 *   status: "queued" | "running" | "completed" | "failed";
 *   total: number;
 *   completed: number;
 *   progress: number;
 *   results: BatchScanResult[];
 *   error: string | null;
 * }} BatchScanStatus
 */
/**
 * @typedef {{ id: string; kind: "domain" | "url" | "text"; value: string; created_at: string }} LocalAllowlistEntry
 */
/**
 * @typedef {{
 *   id: string;
 *   job_id: string;
 *   item_id: string;
 *   input: string;
 *   predicted_label: string;
 *   confidence: number;
 *   reason: string;
 *   red_flags: Array<{ code: string; label: string; severity: string; evidence: string }>;
 *   created_at: string;
 * }} FalsePositiveFeedback
 */

const BASE = import.meta.env.VITE_API_BASE || "/api";

const instance = axios.create({
  baseURL: BASE,
  timeout: 60_000,
});

export async function textCheck(text) {
  return instance.post("/text_check", { text });
}
export async function urlCheck(url) {
  return instance.post("/url_check", { url });
}
export async function imageCheckFile(file) {
  const form = new FormData();
  form.append("image_file", file);
  return instance.post("/image_check", form, {
    headers: { "Content-Type": "multipart/form-data" },
  });
}
export async function chatMultipart(query, file) {
  const form = new FormData();
  form.append("query", query);
  if (file) form.append("file", file);
  return instance.post("/chat_multipart", form, {
    headers: { "Content-Type": "multipart/form-data" },
  });
}

/** @param {File} file @returns {Promise<import("axios").AxiosResponse<BatchScanStatus>>} */
export async function startBatchScan(file) {
  const form = new FormData();
  form.append("file", file);
  return instance.post("/batch_scan", form);
}

/** @param {string} jobId @returns {Promise<import("axios").AxiosResponse<BatchScanStatus>>} */
export async function getBatchScan(jobId) {
  return instance.get(`/batch_scan/${encodeURIComponent(jobId)}`);
}

/**
 * @param {string} jobId
 * @param {string} itemId
 * @param {string} [reason]
 * @returns {Promise<import("axios").AxiosResponse<FalsePositiveFeedback>>}
 */
export async function markBatchFalsePositive(jobId, itemId, reason = "") {
  return instance.post(
    `/batch_scan/${encodeURIComponent(jobId)}/results/${encodeURIComponent(itemId)}/false_positive`,
    { reason },
  );
}

/** @returns {Promise<import("axios").AxiosResponse<LocalAllowlistEntry[]>>} */
export async function getLocalAllowlist() {
  return instance.get("/allowlist");
}

/**
 * @param {"domain" | "url" | "text"} kind
 * @param {string} value
 * @returns {Promise<import("axios").AxiosResponse<LocalAllowlistEntry>>}
 */
export async function addLocalAllowlistEntry(kind, value) {
  return instance.post("/allowlist", { kind, value });
}

/** @param {string} entryId */
export async function deleteLocalAllowlistEntry(entryId) {
  return instance.delete(`/allowlist/${encodeURIComponent(entryId)}`);
}

/** @returns {Promise<import("axios").AxiosResponse<FalsePositiveFeedback[]>>} */
export async function getFalsePositiveFeedback() {
  return instance.get("/feedback/false-positives");
}
