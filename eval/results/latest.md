Evaluated 2026-10-27: 12 scenarios x 2 runs (10 scam runs, 14 benign runs), text replay at real-time speed.

| Metric | Tripwire (Tier 1 + CaseJudge) | Tier-1 score alone (ablation) |
|---|---|---|
| Scam detection rate (hard stop) | **100%** | 80% |
| False-alarm rate (hard stop on benign) | **0%** | 0% |
| Median time to detection | **27.0 s** | 36.0 s |
| Scams stopped before money was asked for | **50%** | |
| Benign runs that got a spoken nudge | 0% | |
| Model calls per run (Tier 1 / Tier 2) | 8.8 / 1.1 | |

| Scenario | Kind | Result per run | Time to detection (s) | Before money ask |
|---|---|---|---|---|
| `benign_antivirus_alert` | benign | log, log | -, - | -, - |
| `benign_family_allowlisted` | benign | log, log | -, - | -, - |
| `benign_family_remote_help` | benign | log, log | -, - | -, - |
| `benign_granddaughter_gift_card` | benign | log, log | -, - | -, - |
| `benign_grandson_banking` | benign | log, log | -, - | -, - |
| `benign_real_bank_call` | benign | log, log | -, - | -, - |
| `benign_update_with_son` | benign | log, log | -, - | -, - |
| `scam_bank_safe_account` | scam | hard_stop, hard_stop | 28.0, 28.2 | no, no |
| `scam_browser_lock_quickassist` | scam | hard_stop, hard_stop | 16.9, 20.6 | -, - |
| `scam_government_crypto` | scam | hard_stop, hard_stop | 28.5, 26.9 | no, no |
| `scam_pc_safeguard` | scam | hard_stop, hard_stop | 18.4, 19.3 | yes, yes |
| `scam_refund_quickassist` | scam | hard_stop, hard_stop | 27.1, 33.5 | yes, yes |
