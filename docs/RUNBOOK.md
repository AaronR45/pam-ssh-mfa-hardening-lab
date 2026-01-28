# Runbook

This runbook matches the repo’s templates and scripts. Use it for repeatable, auditable changes.

## Goal

1) Enforce MFA for interactive SSH logins using PAM + Google Authenticator (TOTP).  
2) Enforce network-aware access controls with `pam_access` guardrails.  
3) (Optional) Restrict login times with `pam_time`.

## Recommended SSH/PAM strategy

- Prompt order: **TOTP verification code**, then **password** (or public key + TOTP, depending on your policy).
- Keep at least one **break-glass path** (console/VM snapshot, etc.) while iterating.
- See [`docs/LOCKOUT_RISK.md`](LOCKOUT_RISK.md) for a verification checklist.

## Files that matter

- `/etc/pam.d/sshd`  
  - must call `pam_google_authenticator.so` in the auth stack
  - should call `pam_access.so` in the account stack
  - optional: `pam_time.so` in the account stack

- `/etc/ssh/sshd_config`  
  - must keep PAM enabled (`UsePAM yes`)
  - must allow interactive auth as needed for PAM MFA
  - should use `AuthenticationMethods` to require your intended factors

- `/etc/security/access.conf`  
  - ordered allow/deny rules for `pam_access`

- `/etc/security/time.conf` (optional)  
  - ordered time rules for `pam_time`

## Implementation steps

1) Install module  
2) Initialize TOTP for each user  
3) Update `/etc/pam.d/sshd` to enforce `pam_google_authenticator.so`  
4) Update `sshd_config` to permit keyboard-interactive as required  
5) Add `pam_access` controls and verify rule ordering  
6) Restart SSH and validate with test accounts  
7) Run audit and store outputs (JSON + terminal capture)

## Validation

Use the included test matrix and offline evaluator:

- `tests/test_matrix.csv` provides example cases (24 rows)
- `scripts/validate_access_conf.py` simulates `pam_access` matching for the policy template

For real on-host testing, create representative accounts in each group and test from each source network (VPN / lab / jumpbox / etc.), capturing:
- success/deny outcomes
- prompts shown (verification code, password, etc.)
- audit output

## Evidence guidance

See `docs/EVIDENCE_REDACTION.md` for what to remove before publishing screenshots/logs.
