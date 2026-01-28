# Automated SSH Hardening & Compliance Lab

![CI Status](https://github.com/AaronR45/pam-ssh-mfa-hardening-lab/actions/workflows/ci.yml/badge.svg)

A production-grade implementation of **SSH Multi-Factor Authentication (MFA)** and **Network-Aware Access Control**, demonstrating automated security compliance, idempotent hardening, and policy-as-code principles.

This repository provides a repeatable, auditable workflow for securing Linux SSH access using `pam_google_authenticator` and `pam_access`.

## Core Capabilities

- **Automated Hardening**: Shell scripts (`scripts/apply_hardening.sh`) that safely apply MFA and access controls with built-in preflight checks, backups, and rollback capabilities.
- **Idempotent Deployment**: Scripts detect existing configurations to prevent duplication or drift.
- **Policy-as-Code**: Access rules defined in `config/access.conf.example` are validated offline against a test matrix before deployment.
- **Continuous Compliance**: An automated audit script (`scripts/audit_pam_ssh_mfa.py`) verifies that the live configuration matches the security policy.

## CompTIA Security+ (SY0-701) Alignment

This project directly maps to the following CompTIA Security+ domains and objectives:

| Domain | Objective | Description | Implementation |
| :--- | :--- | :--- | :--- |
| **1.0 General Security Concepts** | 1.2 | **Identity and Access Management (IAM)** - MFA, Access Control | Implementation of TOTP MFA and `pam_access` rules. |
| **3.0 Security Architecture** | 3.3 | **Host Hardening** - Secure Configuration | Hardening `sshd_config` and PAM stacks. |
| **4.0 Security Operations** | 4.1 | **Monitoring and Auditing** - Log Review, Compliance | Automated audit scripts and configuration validation. |

## Quick Start

### 1. Prerequisites

- Linux (Debian/Ubuntu/Kali) with `openssh-server`.
- Root access.

### 2. Deployment Workflow

**Step 1: Apply Hardening**
This script backs up your configs, validates the current state, and applies the new security controls.
```bash
sudo ./scripts/apply_hardening.sh
```

**Step 2: Verify Compliance**
Run the audit script to confirm the configuration aligns with the policy.
```bash
sudo ./scripts/audit_pam_ssh_mfa.py
```

**Step 3: Validate Access Policy (Offline)**
Simulate access attempts against your policy file to ensure rules logic is correct.
```bash
python3 ./scripts/validate_access_conf.py \
  --access-conf config/access.conf.example \
  --matrix tests/test_matrix.csv
```

## Demonstration

### Audit Output

![Audit Passed](media/placeholder_audit.png)

*The audit script returns `0` (PASS) only if all required security controls are active.*

### MFA Prompt

![MFA Prompt](media/placeholder_mfa.png)

*SSH login requires a Time-Based One-Time Password (TOTP) from Google Authenticator.*

## Safety & Rollback

> **⚠️ Critical:** Always keep a backup root shell open when modifying SSH configurations.

Refer to [`docs/LOCKOUT_RISK.md`](docs/LOCKOUT_RISK.md) for a comprehensive safety checklist.

If a deployment fails validation, the script attempts an automatic rollback. To manually restore the last known good configuration:

```bash
sudo ./scripts/rollback.sh --latest
```

## Repository Structure

```
.
├── config/                 # Security policy templates (Policy-as-Code)
├── docs/                   # Operational documentation (Runbooks, Risk)
├── media/                  # Evidence and demo assets
├── scripts/                # Automation for hardening, rollback, and auditing
├── tests/                  # Test matrices and fixtures
└── .github/workflows/      # CI/CD pipeline for automated testing
```

## Maintenance Log

| Timestamp | Date | Version Tag | Summary of Change |
| :--- | :--- | :--- | :--- |
| 2025-05-20 14:00 EST | May 20, 2025 | v1.0.0-stable | Initial production release with automated auditing and compliance checking. |
| 2025-05-21 10:00 EST | May 21, 2025 | v1.0.1-patch | Fixed CI pathing for Ubuntu runners and enhanced policy verification output. |

## License

MIT (see `LICENSE`).
