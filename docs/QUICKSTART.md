# Quickstart (Debian/Kali/Ubuntu)

> **⚠️ Warning:** This project changes SSH authentication. You risk locking yourself out.
> **Read [`docs/LOCKOUT_RISK.md`](LOCKOUT_RISK.md) before proceeding.**

## 1) Prereqs

- OpenSSH server installed (`openssh-server`)
- PAM enabled (default on Debian-based distros)
- Google Authenticator PAM module:
  - Debian/Ubuntu/Kali: `libpam-google-authenticator`

Install:
```bash
sudo apt update
sudo apt install -y openssh-server libpam-google-authenticator
```

## 2) Create TOTP secrets for each user

For each SSH user:
```bash
google-authenticator -t -d -f -r 3 -R 30 -W
```

That generates `~/.google_authenticator`. Protect it:
```bash
chmod 0400 ~/.google_authenticator
```

## 3) Apply hardening (recommended)

This script:
- backs up current configs under `/var/backups/pam-ssh-mfa-hardening/<timestamp>/`
- applies template snippets for PAM + sshd
- enables `pam_access` enforcement for SSH

Run:
```bash
sudo ./scripts/apply_hardening.sh
```

## 4) Restart SSH safely

On systemd:
```bash
sudo systemctl restart ssh
sudo systemctl status ssh --no-pager
```

Keep your existing session open; test a new session:
```bash
ssh <user>@<host>
```

## 5) Audit / drift check

```bash
sudo ./scripts/audit_pam_ssh_mfa.py
sudo ./scripts/audit_pam_ssh_mfa.py --json
```

## Rollback

```bash
sudo ./scripts/rollback.sh --latest
```
