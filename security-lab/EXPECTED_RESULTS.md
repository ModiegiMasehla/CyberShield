# Expected Results (verified against the analyzers)

## Log files (POST /api/v1/tools/logs/analyze)

| File | Failed logins by IP | Sensitive paths | Alerts |
|---|---|---|---|
| sample-logs/auth.log | 192.168.56.20: 7 | 0 | BRUTE_FORCE MEDIUM (192.168.56.20) |
| sample-logs/auth_bruteforce_high.log | 192.168.56.77: 25 | 0 | BRUTE_FORCE HIGH (192.168.56.77) |
| sample-logs/auth_multiple_sources.log | 192.168.56.20: 6, 192.168.56.99: 21 | 0 | BRUTE_FORCE MEDIUM (.20), BRUTE_FORCE HIGH (.99) |
| sample-logs/auth_normal.log | 192.168.56.31: 4 | 0 | none (below the threshold of 5) |
| sample-logs/web_access_probing.log | none | 12 | SUSPICIOUS_ACTIVITY MEDIUM (web-log) |
| sample-logs/web_access_normal.log | none | 0 | none |

Rules: 5 or more failures from one IP is BRUTE_FORCE (HIGH at 20 or more, otherwise MEDIUM). 10 or more sensitive-path requests is SUSPICIOUS_ACTIVITY.

## Passwords (POST /api/v1/tools/password/analyze)

| Password | Score | Strength |
|---|---|---|
| password123 | 0 | Very Weak |
| 123456 | 0 | Very Weak |
| qwerty | 0 | Very Weak |
| letmein | 0 | Very Weak |
| MyDogRex | 30 | Weak |
| Welcome1 | 45 | Weak |
| aaaa1111AAAA | 60 | Moderate |
| Summer2024! | 60 | Moderate |
| correct-horse-battery-staple-92! | 70 | Moderate |
| Tr0ub4dor&3-horse-Staple | 85 | Strong |
| k9#Lm2$vQx7!pTz4 | 85 | Strong |

Known limitation: aaaa1111AAAA is rated Moderate because the analyzer scores character variety and does not penalize runs of 4+ repeated characters or dictionary-style patterns. Good example to discuss in the video or a future improvement.

## URLs (POST /api/v1/tools/url/analyze)

| URL | Risk | Score |
|---|---|---|
| https://example.com | LOW | 0 |
| https://www.wethinkcode.co.za/about | LOW | 0 |
| http://example.com/login | MEDIUM | 30 |
| http://192.168.1.5/login?redirect=http://evil.com%2Fx | HIGH | 70 |
| https://secure.login.account.verify.bank.example.com/signin | LOW | 10 |
| https://example.com/redirect?url=https://other.example.org | LOW | 10 |
| https://user@example.com/reset | LOW | 15 |
| https://xn--exmple-cua.com/login | LOW | 15 |
| ftp://files.example.com/data | HIGH | 90 |
| not-a-url | HIGH | 90 |

Known limitation: the @ and xn-- (punycode lookalike) cases only score LOW because each indicator adds a small score on its own.

## Scan targets (POST /api/v1/tools/network/scan, admin or analyst)

- 127.0.0.1, 192.168.56.10, 10.0.0.5: accepted
- 8.8.8.8, 203.0.113.10: rejected with HTTP 400 (public address)
- localhost, example.com: rejected with HTTP 400 (must be an IP address in safe lab mode)
