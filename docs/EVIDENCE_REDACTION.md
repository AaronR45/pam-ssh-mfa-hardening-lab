# Evidence redaction guidelines

If you publish screenshots or terminal output:

## Remove
- Hostnames, public IPs, internal IP schemas if sensitive
- Usernames tied to real identities
- QR codes / TOTP secrets (`~/.google_authenticator`)
- Any copied “emergency scratch codes”
- Private keys / known_hosts lines with identifiers

## Keep (helpful for recruiters)
- The **flow**: “Verification code:” then “Password:”
- Key config lines:
  - `UsePAM yes`
  - interactive auth / `AuthenticationMethods`
  - `pam_google_authenticator.so` and `pam_access.so` placement in `/etc/pam.d/sshd`
- Audit script outputs showing “PASS/FAIL” checks with counts

## Recommended: separate “private evidence”
Store raw screenshots in `private/evidence/` (gitignored) and create redacted versions under `docs/evidence/` if you want them public.
