# Section 7 — Scam Shield Evaluation Results

## Run configuration

- **Run time (UTC):** 2026-11-21T17:01:10+00:00
- **Dataset:** `scripts/eval_dataset.json` — 30 balanced, labeled synthetic samples.
- **Execution:** Direct calls to `app.predictors.predict_text_probs` and `predict_url_probs`; text, SMS, email, script, and chat use the text predictor, while URLs use the URL predictor.
- **Mode:** Offline; NVIDIA calls disabled; local models are used when available, with dataset-intelligence and heuristic fallbacks.
- **Local model assets:** text: heuristic fallback; URL: heuristic fallback

## Summary

The detector correctly classified **20 of 30** samples (66.7%). It found **7 of 15** scam samples and correctly cleared **13 of 15** legitimate samples.

Precision was **77.8%** and specificity was **86.7%**, while recall was **46.7%**. Precision and specificity are the strongest aggregate measures in this run; recall also means **8 scam samples were missed**, so this benchmark does not support a claim of production-ready detection.

## Aggregate metrics

| Metric | Result |
|---|---:|
| TP | 7 |
| TN | 13 |
| FP | 2 |
| FN | 8 |
| Accuracy | 66.7% |
| Precision | 77.8% |
| Recall | 46.7% |
| Specificity | 86.7% |
| F1-score | 58.3% |
| Average latency | 342.27 ms |
| P95 latency (nearest-rank) | 0.25 ms |
| Maximum latency | 10267.39 ms |

## Results by input type

| Type | Samples | Accuracy |
|---|---:|---:|
| chat | 5 | 3/5 (60.0%) |
| email | 5 | 4/5 (80.0%) |
| script | 5 | 3/5 (60.0%) |
| sms | 5 | 2/5 (40.0%) |
| text | 5 | 5/5 (100.0%) |
| url | 5 | 3/5 (60.0%) |

## False positives

- `url-legit-01` (url): expected **legitimate**, predicted **scam** (95.0% confidence) — https://www.gov.uk/government/organisations
- `url-legit-02` (url): expected **legitimate**, predicted **scam** (95.0% confidence) — https://www.nhs.uk/nhs-services/gps/

## False negatives

- `sms-scam-01` (sms): expected **scam**, predicted **legitimate** (60.0% confidence) — Final notice: your toll payment is overdue. Pay now at http://toll-payments-confirm.xyz or a penalty will apply.
- `sms-scam-02` (sms): expected **scam**, predicted **legitimate** (60.0% confidence) — A delivery fee is required today. Send the money with a gift card to reschedule your parcel.
- `sms-scam-03` (sms): expected **scam**, predicted **legitimate** (60.0% confidence) — Bank security: share the one-time code we just sent to stop your account from being suspended.
- `email-scam-02` (email): expected **scam**, predicted **legitimate** (75.0% confidence) — Subject: Overdue invoice. Transfer the outstanding balance to this new bank account within 24 hours to avoid legal action.
- `script-scam-01` (script): expected **scam**, predicted **legitimate** (95.0% confidence) — JavaScript snippet reads document.cookie and sends the collected values to an unfamiliar external server.
- `script-scam-02` (script): expected **scam**, predicted **legitimate** (95.0% confidence) — A script decodes a hidden command, runs it without user confirmation, and retrieves the next stage from a remote host.
- `chat-scam-01` (chat): expected **scam**, predicted **legitimate** (95.0% confidence) — Hello, I am from your bank's security team. Your account is at risk; send me the one-time password so I can protect it.
- `chat-scam-02` (chat): expected **scam**, predicted **legitimate** (60.0% confidence) — I am your manager and need an urgent favor. Buy gift cards now and send me the redemption codes.

## Evaluation notes

- “Scam” combines phishing and malware URL predictions; all non-`benign` URL classes count as positive.
- Latency is measured around the direct predictor call and includes its configured model/provider and local dataset-intelligence behavior, but excludes HTTP transport and report generation.
- The average and maximum include first-call dataset-index initialization. The 10267.39 ms maximum raises the average, while nearest-rank p95 uses rank 29 of 30 and excludes that single maximum; the p95 should not be read as a full service-response guarantee.
- The predictor's confidence is its winning class score and has not been calibrated against real-world outcomes.
- The per-type accuracy table has only five samples per type, so one result changes a type's accuracy by 20 percentage points.
- This small synthetic dataset is a smoke-test benchmark, not a substitute for a representative, independently labeled production evaluation.

## What to improve next

- Review the false negatives first, especially requests for one-time codes, gift cards, toll or delivery payments, and suspicious scripts.
- Review the false positives on the government and health-service URLs before increasing URL risk thresholds.
- Expand the independently labeled dataset and rerun it after any detector change; do not treat these 30 samples as proof of general accuracy.
