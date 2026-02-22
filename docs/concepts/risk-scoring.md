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

## Deep Scan Trigger
To optimize performance, Deep Scan is only triggered if the **Fast Scan** produces a risk score >= `0.20` (config `deep_scan_trigger`).
