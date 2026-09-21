# Sources and course alignment

Reviewed 21 September 2026. Page numbers refer to PDF pages. The design choices and test cases are specific to these projects.

## Supplied course documents

| ID | Source | Relevant pages / use |
| --- | --- | --- |
| L0 | `checkpoint 1.txt` | Both Week 4 deliverable lists: short design, diagram, threat model, crypto/stack, sessions, initialized repository and README. |
| L1 | `Introduction to Web Application Security (1).pdf` | pp. 13-16: OWASP 2025 categories and course sequence; pp. 23-26: input validation, configuration and transport. |
| L2 | `Client-Server Communication-26.pdf` | pp. 24-28: transport/HTTPS; pp. 39-40: cookies and SameSite. |
| L3 | `Bypassing Client-Side Controls_.pdf` | pp. 10-14: hidden fields/cookies; pp. 26-27: script validation; pp. 41-43: cookie security and server checks. |
| L4 | `Week 3 - HTML INJECTION AND CONTENT SPOOFING.pdf` | pp. 1-3: HTML injection, fake forms and plaintext spoofing; pp. 8-9: HTML rendering hazards. |
| L5 | `Week 4 - JavaScript and JavaScript Injection Attacks.pdf` | pp. 15-21: XSS types and dangerous sinks; pp. 30-42: validation, encoding, CSP and nosniff. |
| L6 | `Week 4 - CROSS-SITE SCRIPTING.pdf` | pp. 2-3: consequences and HttpOnly limits; pp. 7-12: reflected, stored and DOM XSS. |

The [course repository](https://github.com/TRAPPAWA/ics0027-practice-labs) lists XSS in Week 5. This submission follows the supplied PDFs, which place it in Week 4.

## Official technical references

- **O1:** [OWASP Top 10:2025](https://top10.owasp.org/2025/) - category names and taxonomy. The older 2021 identifiers are not used in these threat tables.
- **O2:** [Django 5.2 security](https://docs.djangoproject.com/en/5.2/topics/security/) - framework protection boundaries and deployment considerations.
- **O3:** [Django 5.2 sessions](https://docs.djangoproject.com/en/5.2/topics/http/sessions/) - database sessions and identifier rotation.
- **O4:** [cryptography authenticated encryption API](https://cryptography.io/en/latest/hazmat/primitives/aead/) - AESGCM, nonce requirements, AAD and authentication failures.
- **O5:** [argon2-cffi parameter selection](https://argon2-cffi.readthedocs.io/en/stable/parameters.html) and [OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) - memory-hard derivation and deployment benchmarking. The vault's explicit parameters are a design choice, not a claim to use the library defaults.
- **O6:** [Caddy automatic HTTPS](https://caddyserver.com/docs/automatic-https) - certificate management and HTTPS deployment plan.

No obsolete browser XSS auditor is relied on as a control. Output encoding is context-specific; URL encoding alone does not make `javascript:` URLs safe. CSP adds defense in depth and does not replace escaping or authorization.
