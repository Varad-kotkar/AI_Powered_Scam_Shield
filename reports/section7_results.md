# Section 7 — Scam Shield Evaluation Results

**Run time (UTC):** 2026-11-21T15:29:29+00:00  
**Dataset:** `scripts/eval_dataset.json` — 30 balanced, labeled synthetic samples  
**Execution:** Direct calls to `app.predictors.predict_text_probs` and `predict_url_probs`; text, SMS, email, script, and chat use the text predictor, while URLs use the URL predictor.
**Mode:** Offline; NVIDIA calls disabled; local models are used when available, with dataset-intelligence and heuristic fallbacks.
**Local model assets:** text: heuristic fallback; URL: heuristic fallback

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
| F1-score | 58.3% |
| Average latency | 396.41 ms |
| P95 latency (nearest-rank) | 0.30 ms |
| Maximum latency | 11891.56 ms |

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
- The average and maximum include first-call initialization; a single cold-start outlier can exceed the nearest-rank p95 on this 30-sample set.
- This small synthetic dataset is a smoke-test benchmark, not a substitute for a representative, independently labeled production evaluation.
