# Risk Scoring

Verdict determination in DocFirewall is probabilistic, not just binary.

## Calculation
Each finding contributes to the total risk score based on its severity and confidence.

$$ Risk = 1.0 - \prod (1.0 - (Severity \times Confidence)) $$

Where Severity is:
-   **CRITICAL**: 1.0
-   **HIGH**: 0.7
-   **MEDIUM**: 0.4
-   **LOW**: 0.1

## Verdict Thresholds

The settings in `config.thresholds` determine the final outcome.

| Score | Verdict | Action |
|---|---|---|
| `>= 0.70` | **BLOCK** | The file is definitely malicious. Reject it. |
| `>= 0.35` | **FLAG** | Suspicious. Route to human review or sandbox. |
| `< 0.35` | **ALLOW** | File appears safe. |

Thresholds are empirically calibrated via `scripts/calibrate_thresholds.py` (ROC-AUC = 1.0 on 1 185 labeled records). See `docs/risk_model.md` for the full calibration report.

## Finding Deduplication

Multiple detectors can fire on the same document region (e.g., the same injection phrase detected by both Layer 1 Aho-Corasick and Layer 2 regex). Without deduplication, two low-confidence findings would multiply into an artificially high risk score.

Findings are grouped by `threat_id` before aggregation; the max confidence per group is taken rather than stacking all findings multiplicatively. This prevents two `p ≈ 0.5` findings from combining to `≈ 0.75` and crossing the BLOCK threshold when they are not truly independent signals.

## Deep Scan Trigger
To optimize performance, Deep Scan is only triggered if the **Fast Scan** produces a risk score >= `0.20` (config `deep_scan_trigger`).
