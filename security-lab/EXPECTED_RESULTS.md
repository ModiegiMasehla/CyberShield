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
| Welcome1 | 25 | Weak |
| aaaa1111AAAA | 45 | Weak |
| Summer2024! | 30 | Weak |
| correct-horse-battery-staple-92! | 90 | Strong |
| Tr0ub4dor&3-horse-Staple | 100 | Strong |
| k9#Lm2$vQx7!pTz4 | 95 | Strong |

Pattern checks: common words (including leet-speak such as `p@ssw0rd`), keyboard/sequence runs, years and runs of 4+ identical characters lower the score, and a pattern-based password shorter than 16 characters can never be rated Strong. Length bonuses start at 16 characters, so long passphrases are rated fairly.

## URLs (POST /api/v1/tools/url/analyze)

| URL | Risk | Score |
|---|---|---|
| https://example.com | LOW | 0 |
| https://www.wethinkcode.co.za/about | LOW | 0 |
| http://example.com/login | MEDIUM | 30 |
| http://192.168.1.5/login?redirect=http://evil.com%2Fx | HIGH | 70 |
| https://secure.login.account.verify.bank.example.com/signin | LOW | 10 |
| https://example.com/redirect?url=https://other.example.org | LOW | 10 |
| https://user@example.com/reset | MEDIUM | 40 |
| https://xn--exmple-cua.com/login | MEDIUM | 30 |
| ftp://files.example.com/data | HIGH | 90 |
| not-a-url | HIGH | 90 |

URL checks: `user@host` (embedded credentials, +40) and punycode `xn--` hostnames (+30) now reach MEDIUM. An `@` or `xn--` inside the path or query string is not suspicious and is no longer flagged. Obfuscated numeric hosts such as `http://2130706433/` add +25.

## Scan targets (POST /api/v1/tools/network/scan, admin or analyst)

- 127.0.0.1, 192.168.56.10, 10.0.0.5: accepted
- 8.8.8.8, 203.0.113.10: rejected with HTTP 400 (public address)
- localhost, example.com: rejected with HTTP 400 (must be an IP address in safe lab mode)
