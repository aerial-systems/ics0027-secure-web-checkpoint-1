# File manager progress

Checkpoint 2, checked 29 October 2026. The file manager builds on checkpoint 1. The password manager remains a separate design and starter option. This note covers the file manager only.

## Implemented

- Server-rendered account registration and login with Django password validation and salted Argon2id hashing.
- Database sessions, rotation through Django login, POST logout, 15-minute idle and 8-hour absolute expiry. Production and development-TLS cookies are Secure, HttpOnly and SameSite=Strict.
- CSRF on every form, no mutating GET, script-free CSP, autoescaped display names and attachment-only downloads.
- Owner-filtered listing, upload, download, rename and delete. Missing/unowned UUIDs return the same 404.
- 10 MiB per file and 100 MiB per user. A bounded memory upload handler avoids Django's temporary plaintext files; total request length is limited and actual received file bytes are counted. Allowed extensions: TXT, PDF, PNG, JPG/JPEG.
- AES-256-GCM file encryption with a new 32-byte data key and 12-byte data nonce per upload. Data keys are wrapped under a separately stored 32-byte master key, using fresh wrapping nonces and distinct owner/file-bound AAD. A database uniqueness constraint protects wrapping-nonce reuse.
- Decryption authenticates the complete ciphertext before returning bytes. Modified/swapped ciphertext fails closed.
- Atomic quota reservation, release, file writes and rename audit logging. Audit events exclude passwords, keys and file contents.
- Atomic fixed-window account/IP attempt limits: 5/account and 20/direct source IP per 15-minute bucket. This conservatively counts all sign-in attempts, including successful ones; a boundary can allow attempts across two adjacent buckets. The IP counter is checked first, so a blocked IP cannot create more username counters. Counters older than 30 minutes are removed on the next attempt. It is not a sliding-window limiter.
- A loopback HTTPS development server with TLS 1.2 minimum and a locally generated seven-day certificate. A client explicitly trusting that certificate verified a 200 health response without disabling verification.

## Storage

Ciphertext is stored in a BinaryField in the private SQLite database. Encrypted data, metadata and quota updates share one transaction, so there are no separate ciphertext files to leave orphaned. The browser cannot access storage directly. The master key is stored separately and excluded from database backups. The checkpoint 1 drawing records the earlier filesystem design.

## Verification

On 29 October, all 40 file-manager tests passed, Django reported no issues, and the migration check found no changes. Coverage includes owner checks, encryption tampering, quota and audit rollback, CSRF, session expiry, unsafe names, key failures and rate limits. Two independent-connection SQLite races also passed in five disposable file-backed database runs. They check consistent storage and quota under contention; they do not establish production availability.

A fresh virtual environment installed all eight pinned dependencies. A clean copy, without existing storage, completed migrations and key initialization, passed Django checks and all 40 tests. The unchanged password manager passed its 9 starter tests earlier that day. Migration drift and whitespace checks passed; migration 0003 was applied locally.

Migrations and initial key setup completed without replacing an existing key. Development TLS was tested with certificate validation enabled.

Brave displayed the live local interface. The server is a coursework development server; no deployment was performed.

## Remaining work

The extension allowlist is not full content-format validation or malware scanning. There is no password recovery/MFA, key rotation/version migration, backup restoration test, distributed deployment, production load/race test, email verification or account-creation limiter. Forced upload/rename/delete database failures now roll back and return controlled errors. Wider outage and production-load behaviour still needs testing. Denied object lookups now produce audit events with keyed session tags, actor, time, direct IP, object and outcome, but no alerts; audit retention/cleanup and account/session revocation beyond logout remain to be finished. Master-key OS permissions must be verified in the actual deployment. Request buffering outside Django and worker concurrency limits need production proxy configuration.

Alert thresholds and a fully versioned key lifecycle remain planned. The development certificate is local and requires explicit trust. Keep real secrets and files out of the draft.

## Run from repository root

```sh
umask 077
. .venv/bin/activate
python file-manager/manage.py migrate
# Run only if no existing key exists; never replace a key containing real data.
python file-manager/manage.py init_file_key
python file-manager/manage.py runserver 127.0.0.1:8000
```

Dependencies: `python -m pip install -r requirements.txt`. Export a stable random `DJANGO_SECRET_KEY` for sessions across server restarts; Django does not load .env automatically. The local app has no pre-created real account. Register only a disposable test account and use synthetic files.

For development HTTPS, generate a certificate (keep files ignored and private):

```sh
openssl req -x509 -newkey rsa:2048 -sha256 -days 7 -nodes \
  -keyout file-manager/private-storage/localhost.key \
  -out file-manager/private-storage/localhost.pem \
  -subj /CN=localhost -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'
chmod 600 file-manager/private-storage/localhost.key
python file-manager/dev_https.py
```

Use https://localhost:8443/ with an explicitly trusted local certificate. The localhost private certificate/key and encryption key are gitignored; never include them in a submission. Only regenerate the TLS certificate, not master.key. Public deployment still requires a proper TLS proxy, hostname and deployment verification.

## Checkpoint 2 coverage

The implementation covers account and file flows, server-side encryption/decryption, password hashing, session management and development TLS. Setup instructions are above. Checkpoint 1 and checkpoint 2 have separate commits; this does not demonstrate continuous incremental development between them.

Display names never become storage paths. File lookup is scoped to the signed-in owner. Encryption protects stored file contents if the database alone is stolen; it does not protect them if an attacker also controls the running server and its master key.

Publishing these files is not a Moodle submission or lab verification.
