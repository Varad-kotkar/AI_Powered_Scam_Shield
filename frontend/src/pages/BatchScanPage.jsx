import { useEffect, useState } from "react";
import { Download, FileText, LoaderCircle, ShieldAlert, Trash2, Upload } from "lucide-react";
import NavBar from "../components/NavBar";
import SiteFooter from "../components/SiteFooter";
import {
  addLocalAllowlistEntry,
  deleteLocalAllowlistEntry,
  getBatchScan,
  getFalsePositiveFeedback,
  getLocalAllowlist,
  markBatchFalsePositive,
  startBatchScan,
} from "../api";

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
 * }} BatchResult
 */
/**
 * @typedef {{
 *   job_id: string;
 *   status: "queued" | "running" | "completed" | "failed";
 *   total: number;
 *   completed: number;
 *   progress: number;
 *   results: BatchResult[];
 *   error: string | null;
 * }} BatchJob
 */
/**
 * @typedef {{ id: string; kind: "domain" | "url" | "text"; value: string; created_at: string }} LocalAllowlistEntry
 */
/**
 * @typedef {{
 *   id: string;
 *   predicted_label: string;
 *   confidence: number;
 *   input: string;
 *   reason: string;
 *   red_flags: Array<{ code: string; label: string; severity: string; evidence: string }>;
 *   created_at: string;
 * }} FeedbackItem
 */

/** @param {{ response?: { status?: number; data?: { detail?: unknown } }; message?: string } | null} error */
function apiError(error) {
  const detail = error?.response?.data?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail.map((item) => item?.msg || JSON.stringify(item)).join("; ");
  }
  if (detail && typeof detail === "object") return JSON.stringify(detail);
  return error?.message || "The request could not be completed.";
}

/** @param {string} filename @param {string} content @param {string} mimeType */
function downloadFile(filename, content, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

/** @param {unknown} value */
function csvCell(value) {
  const text = String(value ?? "");
  const safeText = /^[\s]*[=+\-@]/.test(text) ? `'${text}` : text;
  return `"${safeText.replace(/"/g, '""')}"`;
}

/** @param {BatchResult[]} results */
function formatCsv(results) {
  const columns = ["index", "input", "kind", "label", "confidence", "probs", "red_flags", "allowlisted", "error"];
  const rows = results.map((item) => columns.map((column) => {
    const value = ["probs", "red_flags"].includes(column) ? JSON.stringify(item[column]) : item[column];
    return csvCell(value);
  }).join(","));
  return [columns.join(","), ...rows].join("\r\n");
}

export default function BatchScanPage() {
  /** @type {[File | null, import("react").Dispatch<import("react").SetStateAction<File | null>>]} */
  const [file, setFile] = useState(null);
  /** @type {[BatchJob | null, import("react").Dispatch<import("react").SetStateAction<BatchJob | null>>]} */
  const [job, setJob] = useState(null);
  /** @type {[LocalAllowlistEntry[], import("react").Dispatch<import("react").SetStateAction<LocalAllowlistEntry[]>>]} */
  const [allowlist, setAllowlist] = useState([]);
  /** @type {[FeedbackItem[], import("react").Dispatch<import("react").SetStateAction<FeedbackItem[]>>]} */
  const [feedback, setFeedback] = useState([]);
  /** @type {["domain" | "url" | "text", import("react").Dispatch<import("react").SetStateAction<"domain" | "url" | "text">>]} */
  const [allowlistKind, setAllowlistKind] = useState("domain");
  const [allowlistValue, setAllowlistValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    getLocalAllowlist()
      .then((response) => active && setAllowlist(response.data))
      .catch((requestError) => active && setError(apiError(requestError)));
    getFalsePositiveFeedback()
      .then((response) => active && setFeedback(response.data))
      .catch((requestError) => active && setError(apiError(requestError)));
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (!job?.job_id || ["completed", "failed"].includes(job.status)) return undefined;
    let active = true;
    let timeoutId;

    const poll = async () => {
      try {
        const response = await getBatchScan(job.job_id);
        if (!active) return;
        setJob(response.data);
        if (!["completed", "failed"].includes(response.data.status)) {
          timeoutId = window.setTimeout(poll, 900);
        }
      } catch (requestError) {
        if (!active) return;
        setError(apiError(requestError));
        if (requestError?.response?.status === 404) {
          setJob((current) => current && {
            ...current,
            status: "failed",
            error: "This batch job is no longer available. Jobs are held in memory and may be cleared after a server restart.",
          });
          return;
        }
        timeoutId = window.setTimeout(poll, 1800);
      }
    };

    timeoutId = window.setTimeout(poll, 400);
    return () => {
      active = false;
      window.clearTimeout(timeoutId);
    };
  }, [job?.job_id, job?.status]);

  async function submitBatch(event) {
    event.preventDefault();
    if (!file) return;
    setBusy(true);
    setError("");
    setJob(null);
    try {
      const response = await startBatchScan(file);
      setJob(response.data);
    } catch (requestError) {
      setError(apiError(requestError));
    } finally {
      setBusy(false);
    }
  }

  async function addAllowlist(event) {
    event.preventDefault();
    if (!allowlistValue.trim()) return;
    setError("");
    try {
      const response = await addLocalAllowlistEntry(allowlistKind, allowlistValue.trim());
      setAllowlist((current) => [response.data, ...current]);
      setAllowlistValue("");
    } catch (requestError) {
      setError(apiError(requestError));
    }
  }

  async function removeAllowlistEntry(entryId) {
    setError("");
    try {
      await deleteLocalAllowlistEntry(entryId);
      setAllowlist((current) => current.filter((entry) => entry.id !== entryId));
    } catch (requestError) {
      setError(apiError(requestError));
    }
  }

  async function submitFalsePositive(item) {
    if (!job) return;
    setError("");
    try {
      await markBatchFalsePositive(job.job_id, item.item_id);
      setJob((current) => current && ({
        ...current,
        results: current.results.map((result) =>
          result.item_id === item.item_id ? { ...result, feedback_submitted: true } : result,
        ),
      }));
      const response = await getFalsePositiveFeedback();
      setFeedback(response.data);
    } catch (requestError) {
      setError(apiError(requestError));
    }
  }

  const results = job?.results || [];
  const canExport = job?.status === "completed" && results.length > 0;

  return (
    <div className="min-h-screen bg-white text-slate-900">
      <NavBar />
      <main className="mx-auto w-full max-w-5xl px-4 py-10">
        <div className="mb-8">
          <p className="text-sm font-semibold uppercase tracking-wide text-orange-600">Scam Shield tools</p>
          <h1 className="mt-2 text-3xl font-bold">Batch Scan</h1>
          <p className="mt-2 max-w-2xl text-sm text-slate-600">
            Upload a UTF-8 CSV or TXT file with one message or URL per row. Scans run with a server-side concurrency limit,
            and results can be downloaded as CSV or JSON.
          </p>
        </div>

        <section className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
          <form onSubmit={submitBatch} className="flex flex-col gap-4 sm:flex-row sm:items-end">
            <label className="flex-1 text-sm font-medium">
              Batch file
              <input
                type="file"
                accept=".csv,.txt,text/csv,text/plain"
                onChange={(event) => setFile(event.target.files?.[0] || null)}
                className="mt-2 block w-full rounded-lg border border-slate-300 p-2 text-sm"
              />
            </label>
            <button
              type="submit"
              disabled={!file || busy || ["queued", "running"].includes(job?.status)}
              className="inline-flex h-10 items-center justify-center gap-2 rounded-lg bg-slate-900 px-4 text-sm font-semibold text-white disabled:cursor-not-allowed disabled:opacity-50"
            >
              {busy || ["queued", "running"].includes(job?.status)
                ? <LoaderCircle className="h-4 w-4 animate-spin" />
                : <Upload className="h-4 w-4" />}
              Start batch
            </button>
          </form>

          {job && (
            <div className="mt-5" aria-live="polite">
              <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
                <span className="font-semibold capitalize">{job.status}</span>
                <span>{job.completed} / {job.total} scanned ({job.progress}%)</span>
              </div>
              <progress className="mt-2 h-2 w-full" max="100" value={job.progress} aria-label="Batch scan progress" />
              {job.error && <p className="mt-2 text-sm text-red-700">{job.error}</p>}
              {canExport && (
                <div className="mt-4 flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={() => downloadFile("scam-shield-results.json", JSON.stringify({ job_id: job.job_id, results }, null, 2), "application/json")}
                    className="inline-flex items-center gap-2 rounded-lg border border-slate-300 px-3 py-2 text-sm font-medium hover:bg-slate-50"
                  >
                    <Download className="h-4 w-4" /> Export JSON
                  </button>
                  <button
                    type="button"
                    onClick={() => downloadFile("scam-shield-results.csv", formatCsv(results), "text/csv;charset=utf-8")}
                    className="inline-flex items-center gap-2 rounded-lg border border-slate-300 px-3 py-2 text-sm font-medium hover:bg-slate-50"
                  >
                    <Download className="h-4 w-4" /> Export CSV
                  </button>
                </div>
              )}
            </div>
          )}
        </section>

        {error && (
          <div role="alert" className="mt-4 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
            {error}
          </div>
        )}

        {results.length > 0 && (
          <section className="mt-8 space-y-3">
            <h2 className="text-xl font-semibold">Scan results</h2>
            {results.map((item) => (
              <article key={item.item_id} className="rounded-xl border border-slate-200 bg-white p-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-semibold capitalize">{item.label}</span>
                      <span className="text-sm text-slate-500">{(item.confidence * 100).toFixed(1)}% confidence</span>
                      {item.allowlisted && (
                        <span className="rounded-full bg-emerald-100 px-2 py-1 text-xs font-medium text-emerald-800">
                          Local allowlist
                        </span>
                      )}
                    </div>
                    <p className="mt-2 whitespace-pre-wrap break-words text-sm text-slate-700">{item.input}</p>
                    {item.error && <p className="mt-2 text-sm text-red-700">{item.explanation}</p>}
                  </div>
                  {item.label !== "benign" && !item.allowlisted && !item.error && (
                    <button
                      type="button"
                      disabled={item.feedback_submitted}
                      onClick={() => submitFalsePositive(item)}
                      className="rounded-lg border border-slate-300 px-3 py-2 text-xs font-medium hover:bg-slate-50 disabled:opacity-60"
                    >
                      {item.feedback_submitted ? "Feedback recorded" : "Mark as False Positive"}
                    </button>
                  )}
                </div>
                {item.red_flags.length > 0 && (
                  <ul className="mt-3 space-y-1">
                    {item.red_flags.map((flag, index) => (
                      <li key={`${flag.code}-${index}`} className="flex flex-wrap gap-x-2 text-xs">
                        <span className="font-semibold">{flag.label}</span>
                        <span className="uppercase text-slate-500">{flag.severity}</span>
                        <span className="text-slate-600">{flag.evidence}</span>
                      </li>
                    ))}
                  </ul>
                )}
                {!item.error && <p className="mt-3 text-sm text-slate-600">{item.explanation}</p>}
              </article>
            ))}
          </section>
        )}

        <section className="mt-10 grid gap-6 lg:grid-cols-2">
          <div className="rounded-2xl border border-slate-200 p-5">
            <h2 className="flex items-center gap-2 text-lg font-semibold">
              <ShieldAlert className="h-5 w-5 text-orange-600" /> Local allowlist
            </h2>
            <p className="mt-1 text-sm text-slate-600">
              Matching batch entries are treated as benign and skipped. Text entries match exactly; domain entries also match subdomains.
            </p>
            <form onSubmit={addAllowlist} className="mt-4 flex flex-col gap-2 sm:flex-row">
              <select
                value={allowlistKind}
                onChange={(event) => setAllowlistKind(event.target.value)}
                className="rounded-lg border border-slate-300 px-3 py-2 text-sm"
                aria-label="Allowlist entry type"
              >
                <option value="domain">Domain</option>
                <option value="url">URL</option>
                <option value="text">Exact text</option>
              </select>
              <input
                value={allowlistValue}
                onChange={(event) => setAllowlistValue(event.target.value)}
                placeholder="example.com"
                maxLength={512}
                className="min-w-0 flex-1 rounded-lg border border-slate-300 px-3 py-2 text-sm"
              />
              <button type="submit" className="rounded-lg bg-slate-900 px-3 py-2 text-sm font-semibold text-white">
                Add
              </button>
            </form>
            <ul className="mt-4 divide-y divide-slate-100">
              {allowlist.map((entry) => (
                <li key={entry.id} className="flex items-center justify-between gap-3 py-2 text-sm">
                  <span className="min-w-0 break-all"><strong className="capitalize">{entry.kind}</strong>: {entry.value}</span>
                  <button type="button" onClick={() => removeAllowlistEntry(entry.id)} aria-label={`Remove ${entry.value}`} className="shrink-0 rounded p-2 hover:bg-slate-100">
                    <Trash2 className="h-4 w-4" />
                  </button>
                </li>
              ))}
              {allowlist.length === 0 && <li className="py-3 text-sm text-slate-500">No local allowlist entries.</li>}
            </ul>
          </div>

          <div className="rounded-2xl border border-slate-200 p-5">
            <h2 className="flex items-center gap-2 text-lg font-semibold">
              <FileText className="h-5 w-5 text-orange-600" /> False-positive review
            </h2>
            <p className="mt-1 text-sm text-slate-600">Feedback is stored locally for review; it does not automatically change model predictions.</p>
            <ul className="mt-4 max-h-80 divide-y divide-slate-100 overflow-y-auto">
              {feedback.map((item) => (
                <li key={item.id} className="py-3">
                  <div className="flex justify-between gap-2 text-xs text-slate-500">
                    <span className="capitalize">
                      Predicted {item.predicted_label} ({(item.confidence * 100).toFixed(1)}%)
                    </span>
                    <time>{new Date(item.created_at).toLocaleString()}</time>
                  </div>
                  <p className="mt-1 break-words text-sm">{item.input}</p>
                  {item.reason && <p className="mt-1 text-sm text-slate-600">{item.reason}</p>}
                  {item.red_flags.length > 0 && (
                    <p className="mt-1 text-xs text-slate-500">
                      Red flags: {item.red_flags.map((flag) => flag.label).join(", ")}
                    </p>
                  )}
                </li>
              ))}
              {feedback.length === 0 && (
                <li className="py-3 text-sm text-slate-500">No feedback submitted for review.</li>
              )}
            </ul>
          </div>
        </section>
      </main>
      <SiteFooter />
    </div>
  );
}
