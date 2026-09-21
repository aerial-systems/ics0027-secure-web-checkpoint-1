# Test results

Local verification: 21 September 2026, macOS, Python 3.12.13, dependency versions from `requirements.txt`.

| Check | File manager | Password manager |
| --- | --- | --- |
| Install pinned dependencies | Passed (shared environment) | Passed (shared environment) |
| `manage.py migrate --noinput` | Passed all framework migrations | Passed all framework migrations |
| `manage.py check` | No issues | No issues |
| `manage.py test core` | 9 tests passed | 9 tests passed |
| Start real development HTTP server, request `/` and `/health/` | HTTP 200; expected content and no-store | HTTP 200; expected content and no-store |
| Production config with random secret and explicit hostname | Loaded; secure cookie flags and HTTPS redirect verified | Loaded; secure cookie flags and HTTPS redirect verified |
| Missing production signing secret | Startup rejected | Startup rejected |
| Missing production allowed hosts | Startup rejected | Startup rejected |
| `manage.py check --deploy` | No errors; W005 and W021 only | No errors; W005 and W021 only |
| Architecture SVG rendered and visually inspected | Legible; no clipping | Legible; no clipping |

W005 and W021 concern HSTS subdomains and preload. Both need a domain review before deployment. No live service or certificate has been tested.

Each app has nine tests: health/home page, headers, template escaping, Host validation, unavailable routes and methods, Argon2id hashing, session cookies, HTTPS redirect and CSRF rejection. Encryption and login remain unimplemented; their tests are in the [test plan](ACCEPTANCE.md).

CI installs dependencies, runs migrations and repeats the Django checks and tests on Ubuntu with Python 3.12. Actions use pinned commits and read-only permissions.

Readability checks: Python formatting and lint passed; all local Markdown links resolve; both route tables render correctly. Tracked text contains no em or en dashes. Python code has one proxy-trust comment per app.
