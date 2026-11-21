function getConfidence(data) {
  const confidence = Number(data?.confidence);
  if (data?.confidence == null) {
    const label = String(data?.label || "").toLowerCase();
    const probability = Number(data?.probs?.[label]);
    return Number.isFinite(probability) ? probability : null;
  }
  if (Number.isFinite(confidence)) return confidence;

  const label = String(data?.label || "").toLowerCase();
  const probabilities = data?.probs;
  const probability = Number(probabilities?.[label]);
  return Number.isFinite(probability) ? probability : null;
}

export function formatShareWarning(data) {
  const verdict = String(data?.label || "unknown").replace(/[_-]+/g, " ").toUpperCase();
  const confidence = getConfidence(data);
  const redFlags = Array.isArray(data?.red_flags) ? data.red_flags : [];
  const flagLines = redFlags.length
    ? redFlags.map((flag) => {
      const label = String(flag?.label || flag?.code || "Red flag");
      const severity = flag?.severity ? ` (${String(flag.severity).toUpperCase()})` : "";
      const evidence = flag?.evidence ? ` — ${String(flag.evidence).replace(/\s+/g, " ").trim()}` : "";
      return `- ${label}${severity}${evidence}`;
    })
    : ["- No structured red flags identified."];

  return [
    "SCAM SHIELD WARNING",
    `Verdict: ${verdict}`,
    `Confidence: ${confidence === null ? "Unavailable" : `${(confidence * 100).toFixed(1)}%`}`,
    "Key red flags:",
    ...flagLines,
    "",
    "Do not click or pay. Verify through an official website or contact channel.",
  ].join("\n");
}
