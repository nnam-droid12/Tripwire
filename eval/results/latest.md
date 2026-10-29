Evaluated 2026-10-29: 12 scenarios x 1 runs (5 scam runs, 7 benign runs), text replay at real-time speed.

| Metric | Tripwire (Tier 1 + CaseJudge) | Tier-1 score alone (ablation) |
|---|---|---|
| Scam detection rate (hard stop) | **100%** | 80% |
| False-alarm rate (hard stop on benign) | **0%** | 0% |
| Median time to detection | **29.4 s** | 36.2 s |
| Scams stopped before money was asked for | **50%** | |
| Benign runs that got a spoken nudge | 0% | |
| Model calls per run (Tier 1 / Tier 2) | 8.8 / 1.2 | |

| Scenario | Kind | Result per run | Time to detection (s) | Before money ask |
|---|---|---|---|---|
| `benign_antivirus_alert` | benign | log | - | - |
| `benign_family_allowlisted` | benign | log | - | - |
| `benign_family_remote_help` | benign | log | - | - |
| `benign_granddaughter_gift_card` | benign | log | - | - |
| `benign_grandson_banking` | benign | log | - | - |
| `benign_real_bank_call` | benign | log | - | - |
| `benign_update_with_son` | benign | log | - | - |
| `scam_bank_safe_account` | scam | hard_stop | 29.4 | no |
| `scam_browser_lock_quickassist` | scam | hard_stop | 25.9 | - |
| `scam_government_crypto` | scam | hard_stop | 29.6 | no |
| `scam_pc_safeguard` | scam | hard_stop | 24.8 | yes |
| `scam_refund_quickassist` | scam | hard_stop | 35.8 | yes |
