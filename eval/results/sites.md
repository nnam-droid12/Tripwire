Site Check on cloned pages (2026-11-03): 12 cases x 2 runs; the screen is read by Muse Spark Open.

Clones caught: **14/14**. False alarms on real pages: **0/10**.

| Page | Browser's real address | Expected | Fired (run 1 / run 2) |
|---|---|---|---|
| site_shopwave_signin | `https://www.shopwave.com/signin` | nothing (real page) | nothing / nothing ✓ |
| site_shopwave_signin | `https://www.shopwаve.com/signin` | lookalike_domain | lookalike_domain / lookalike_domain ✓ |
| site_shopwave_signin | `https://shopvvave.com/signin` | lookalike_domain | lookalike_domain / lookalike_domain ✓ |
| site_shopwave_signin | `https://shopwave.co/signin` | lookalike_domain | lookalike_domain / lookalike_domain ✓ |
| site_shopwave_signin | `https://shopwave-order-review.help/signin` | brand_domain_mismatch | brand_domain_mismatch / brand_domain_mismatch ✓ |
| site_bank_signin | `https://www.riverbendbank.com/login` | nothing (real page) | nothing / nothing ✓ |
| site_bank_signin | `https://online.riverbendbank.com/login` | nothing (real page) | nothing / nothing ✓ |
| site_bank_signin | `https://riverbend-secure-verify.top/login` | brand_domain_mismatch | brand_domain_mismatch / brand_domain_mismatch ✓ |
| site_bank_signin | `https://riverbendbank.com.account-verify.help/login` | brand_domain_mismatch | brand_domain_mismatch / brand_domain_mismatch ✓ |
| site_fake_window | `https://northgate-rewards.click/claim` | fake_browser_window | brand_domain_mismatch, fake_browser_window / brand_domain_mismatch, fake_browser_window ✓ |
| site_giftcard_shop | `https://www.northgatemarket.com/checkout` | nothing (real page) | nothing / nothing ✓ |
| site_news_article | `https://valleydaily.example/business` | nothing (real page) | nothing / nothing ✓ |
