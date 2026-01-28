# PAM-Based SSH MFA & Access Controls (Linux)

![CI Status](https://github.com/AaronR45/pam-ssh-mfa-hardening-lab/actions/workflows/ci.yml/badge.svg)

A hardened, repeatable lab for enforcing **SSH multi-factor authentication (MFA)** using **PAM + Google Authenticator (TOTP)**, plus **network-aware access controls** with `pam_access` and optional **time-based login windows**.

This repo is built to be *recruiter-readable*: it includes a runbook, config templates, a test matrix, and an automated compliance/audit script that produces repeatable pass/fail output.

## What this lab demonstrates

- **SSH MFA via PAM + Google Authenticator (TOTP)**, enforcing MFA for **100% of interactive SSH logins** during validation testing.
- **`pam_access` guardrails** in `/etc/security/access.conf` with an example policy showing **18 allow/deny rules** across **4 user groups** and **6 source networks**.
- **Automated compliance check** (audit script + alerting hooks) to detect drift in PAM config, `sshd` settings, and access rules.

## Evidence (local / redacted)

A sample capture of:
- **Time control access** via `/etc/security/time.conf` and a resulting SSH denial (page 1)
- **Google Authenticator “Verification code” prompt** during SSH, and key `sshd_config` lines (page 2)

is included **locally** under `private/evidence/` (ignored by git). Use it as a reference and publish only redacted screenshots if you choose.

## Repo layout

```
.
├── config/                         # Example configs (safe to publish)
│   ├── sshd_config.example
│   ├── pam.d.sshd.example
│   ├── access.conf.example
│   └── time.conf.example
├── docs/
│   ├── QUICKSTART.md
│   ├── RUNBOOK.md
│   ├── TESTING.md
│   └── EVIDENCE_REDACTION.md
├── scripts/
│   ├── apply_hardening.sh          # Applies templates with backups + safety rails
│   ├── rollback.sh                 # Restores from backups
│   ├── audit_pam_ssh_mfa.py        # Repeatable compliance check (pass/fail + JSON)
│   ├── validate_access_conf.py     # Offline evaluator for access.conf rule logic
│   └── generate_test_matrix.py     # Emits CSV test matrices
├── tests/
│   ├── test_matrix.csv             # Example 24-case allow/deny matrix
│   └── access_policy_expected.json # Expected policy evaluation results
└── private/                        # Ignored by git (store screenshots, notes)
```

## Quick start

Read: [`docs/QUICKSTART.md`](docs/QUICKSTART.md) for full instructions.

**Typical workflow:**

1. **Apply hardening** (creates backups first, prompts for confirmation)
   ```bash
   sudo ./scripts/apply_hardening.sh
   ```

2. **Run audit** (verify config state)
   ```bash
   sudo ./scripts/audit_pam_ssh_mfa.py
   ```

3. **Validate access policy** (offline test against matrix)
   ```bash
   python3 ./scripts/validate_access_conf.py \
     --access-conf ./config/access.conf.example \
     --matrix ./tests/test_matrix.csv
   ```

## Safety notes

> **⚠️ Risk of Lockout:** Modifying SSH authentication carries a risk of locking yourself out.

- Read **[`docs/LOCKOUT_RISK.md`](docs/LOCKOUT_RISK.md)** before applying changes.
- Always keep a **root console / out-of-band path** open.
- The apply script backs up files and includes a rollback helper.

## License

MIT (see `LICENSE`).
