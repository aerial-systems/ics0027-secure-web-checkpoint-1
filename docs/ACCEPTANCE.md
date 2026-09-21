# Planned security tests

These tests are for features that are not implemented yet. Use local test data, two accounts (Alice and Bob), separate cookie jars and random test keys. Send requests with a proxy or HTTP client. Test only systems you have permission to test.

## Shared and file-manager cases

| Threats | Test procedure | Required result |
| --- | --- | --- |
| F01 / P01 | Alice creates an object. As Bob, replay list/read/update/delete with Alice's UUID and injected owner/vault fields. Also send without a session. | No information or state change; owner mismatch returns 404; unauthenticated request is refused. Verify stored state afterwards. |
| F02 / P02 | Start production without signing secret/allowed hosts; send forged Host and forwarded-protocol headers; probe storage paths. | Invalid config fails startup; invalid Host refused; external client cannot reach backend; no public DB/storage. Confirm trusted proxy overwrites headers. |
| F03 / P03 | Review dependency lock, action SHAs and dependency alerts before release; test install from clean environment. | Reviewed versions and reproducible install; unresolved high-risk advisories block release. |
| F04 | Encrypt equal file bytes twice; inspect DB/storage; try decrypt with wrong key. Restore backup with and without separately recovered KEK. | Different ciphertext; no plaintext/KEK in DB/storage; wrong/missing key fails; correct recovery restores bytes. |
| F05 / P05 | Submit `<img src=x onerror=alert(1)>`, a fake login form and quote-breaking text as filename/title/notes/error input. Test URL/hash input and disable CSP for the escaping check. | Text rendered literally; no added DOM elements, dialogs or outbound requests. No untrusted value reaches an HTML/script sink. Check decrypted payloads too. |
| F05 / P05 | Use a user label reading 'System: re-enter your password' without markup. | Label remains clearly user-authored content, visually separate from actual system messages. |
| F06 | Remove browser limits; forge Content-Length/size/owner; upload 10 MiB + 1 byte and race two quota-crossing requests. | Actual bytes and transactional reservation decide acceptance; oversized/over-quota upload rejected with no plaintext temp file or orphan published object. |
| F07 / P07 | Pre-set session cookie before login; compare after login. Replay old cookie after logout/password change. Advance server clock beyond idle and absolute deadlines while sending activity. | Identifier rotates; old or revoked sessions rejected; activity cannot bypass absolute expiry. Inspect Set-Cookie flags over HTTPS. |
| F07 / P07 | Submit failed logins from same account and rotating IPs, then multiple accounts at one IP; test master failures too. | Both atomic throttles apply as designed, generic responses, bounded work; backoff expires. |
| F08 / P08 | Flip ciphertext/tag/nonce bytes; substitute another object's ciphertext or wrapped key; alter AAD identity/version. | Generic integrity failure; no partial plaintext; audit event recorded; unaffected records remain usable. |
| F09 / P09 | Trigger repeated denied access/tag failure thresholds, then inspect logs and alert destination in a local test sink. | Redacted event and threshold alert; no passwords, content, keys or session IDs. |
| F10 | Simulate full disk, DB commit failure and unavailable key store during upload/download. Restart and run recovery cleanup. | No plaintext released, no successful response, consistent quota/metadata after recovery; staging ciphertext cleaned safely. |
| F11 / P11 | Submit mutation without CSRF token, with wrong origin, by GET, and in an iframe. | CSRF/origin rejection, GET refuses mutation/reveal, frame blocked. SameSite is not the sole check. |

## Additional password-manager cases

| Threats | Test procedure | Required result |
| --- | --- | --- |
| P04 | Create vault and entry; search database, session store and application logs for test plaintext, KEK and DEK. Inspect stored KDF profile. | Only account verifier, salt/profile, wrapped key and authenticated ciphertext persist; no plaintext payload or unwrapped key. |
| P04 / P08 | Force the random nonce generator to repeat a prior entry nonce, including a deleted entry nonce. | Unique ledger blocks reuse; retry before encryption commit or fail safely; never accept reused nonce under the same DEK. |
| P06 | Disable JS; submit too-short or >128-character passphrase, >8 KiB JSON payload, 101st entry and malicious stored KDF cost values. | Server rejects; does not allocate attacker-selected KDF memory; capacity limits apply across simultaneous requests. |
| P10 | Rewrap with new master passphrase; inject transaction failure midway; retry old/new passphrases. | After success only new master unwraps current vault; after rollback old remains valid. Entries still decrypt byte-for-byte. |
| P10 | Change account password without master; attempt to reveal with account password alone; test a lost master. | Account authentication grants no decryption. No reset route silently overwrites or bypasses the vault. |
| P05 / P10 | Reveal test credential, inspect cache headers/browser history, wait 30 seconds, log out and replay reveal. | No URL secret/cache storage; UI clears when implemented; expired session rejected. Clearing is not claimed to erase device memory. |

Record the commit, environment, case ID, inputs and result for each test. Remove secrets from evidence. CI currently tests only the starter.
