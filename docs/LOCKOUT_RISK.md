# Risk of SSH Lockout

When modifying SSH authentication, you risk locking yourself out of the system. Follow this checklist **before** closing your current session or restarting the SSH service.

## Pre-Apply Checklist

- [ ] **Root Shell**: Ensure you have an active root shell (`sudo -i`) in a terminal that will remain open.
- [ ] **Break-Glass Access**: Verify you have out-of-band access (console, VM snapshot, physical access).
- [ ] **Backups**: Confirm the apply script will create backups of `sshd_config`, `pam.d/sshd`, and `access.conf`.

## Verification Checklist (Before Closing Session)

After applying changes and restarting SSH (`systemctl restart ssh`), do **not** close your current session.

1.  **Validate Config Syntax**:
    ```bash
    sudo sshd -t
    ```
    If this produces output, fix the errors immediately.

2.  **Test New Connection**:
    Open a *new* terminal window and attempt to SSH in.
    ```bash
    ssh -v user@host
    ```

3.  **Verify MFA**:
    - Confirm you are prompted for the Verification Code (TOTP).
    - Confirm you can log in successfully.

4.  **Verify Access Control**:
    - If testing allow rules, confirm access.
    - If testing deny rules, confirm rejection.

5.  **Check Logs**:
    Watch auth logs for errors during the test attempt.
    ```bash
    sudo tail -f /var/log/auth.log
    # or
    sudo journalctl -u ssh -f
    ```

## Recovery

If you are locked out and have an open root shell:
1.  Run the rollback script:
    ```bash
    sudo ./scripts/rollback.sh --latest
    ```
2.  Or manually restore files from `/var/backups/pam-ssh-mfa-hardening/`.

If you lost all shell access, use your out-of-band console to restore the files or revert the VM snapshot.
