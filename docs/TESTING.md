# Testing & Validation

## What to validate

### MFA
- SSH interactive login triggers:
  - a **Verification code** prompt (TOTP)
  - followed by **Password** (or your configured 2nd factor)
- MFA is required for *all* interactive SSH logins in scope.

### Access controls (`pam_access`)
- Each user group is allowed only from expected source networks.
- Deny rules cover everything else.
- Rule ordering is correct (first match wins).

### Drift detection
- A later change to PAM, `sshd_config`, or access rules should be caught by:
  - `scripts/audit_pam_ssh_mfa.py`

## Offline policy test (recommended for CI)

```bash
python3 scripts/validate_access_conf.py   --access-conf ./config/access.conf.example   --matrix ./tests/test_matrix.csv
```

## On-host test matrix approach

1) Create 8 test users across the 4 groups  
2) From each of 6 networks, attempt:
   - SSH interactive login
   - record allow/deny and prompts
3) Compare outcomes to expected matrix

The included `tests/test_matrix.csv` shows a 24-case subset to keep testing fast but meaningful.
