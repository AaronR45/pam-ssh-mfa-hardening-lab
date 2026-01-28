#!/usr/bin/env python3
"""audit_pam_ssh_mfa.py

Repeatable compliance check for:
- PAM sshd stack (Google Authenticator MFA + pam_access)
- sshd_config settings required for interactive PAM MFA
- access.conf sanity (presence of rules, catch-all deny, etc.)

Run:
  sudo ./scripts/audit_pam_ssh_mfa.py
  sudo ./scripts/audit_pam_ssh_mfa.py --json
  sudo ./scripts/audit_pam_ssh_mfa.py --root /path/to/alt-root

Exit codes:
  0 = all required checks pass
  2 = one or more required checks failed

JSON Output Schema:
  {
    "overall": "PASS" | "FAIL",
    "missing_files": [ "path/to/missing/file", ... ],
    "results": [
      {
        "id": "check_id",
        "description": "Description of the check",
        "passed": true | false,
        "details": "Details about the result",
        "severity": "required" | "optional"
      },
      ...
    ]
  }
"""

from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple


RE_RULE = re.compile(r"^\s*([+-])\s*:\s*(.*?)\s*:\s*(.*?)\s*$")


@dataclass
class CheckResult:
    """Represents the outcome of a single compliance check."""
    id: str
    description: str
    passed: bool
    details: str
    severity: str = "required"  # required|optional


def read_text(path: str) -> Optional[str]:
    """Reads file content safely, returning None if not found."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except FileNotFoundError:
        return None


def join_root(root: str, rel: str) -> str:
    """Joins a root directory with an absolute-like relative path."""
    if root == "/":
        return rel
    return os.path.join(root.rstrip("/"), rel.lstrip("/"))


def find_line_index(text: str, pattern: str) -> Optional[int]:
    """Returns 0-based line index of first matching regex."""
    rx = re.compile(pattern)
    for i, line in enumerate(text.splitlines()):
        if rx.search(line):
            return i
    return None


def audit_pam_sshd(pam_text: str) -> List[CheckResult]:
    """Audits the PAM configuration for SSHD (MFA and Access Control)."""
    checks: List[CheckResult] = []

    has_google = bool(
        re.search(r"^\s*auth\s+.*pam_google_authenticator\.so\b", pam_text, re.M)
    )
    checks.append(CheckResult(
        id="pam_google_authenticator_present",
        description=(
            "/etc/pam.d/sshd includes pam_google_authenticator.so in auth stack"
        ),
        passed=has_google,
        details=(
            "Found" if has_google
            else "Missing 'pam_google_authenticator.so' in auth stack"
        ),
    ))

    # Prompt order heuristic: ensure GA line appears before common-auth include
    ga_idx = find_line_index(pam_text, r"pam_google_authenticator\.so")
    common_auth_idx = find_line_index(pam_text, r"^\s*@include\s+common-auth\b")
    if ga_idx is not None and common_auth_idx is not None:
        passed = ga_idx < common_auth_idx
        details = (
            f"pam_google_authenticator line={ga_idx+1}, "
            f"common-auth include={common_auth_idx+1}"
        )
    else:
        passed = True
        details = (
            "Could not evaluate prompt-order heuristic "
            "(non-Debian layout or missing markers)."
        )
    checks.append(CheckResult(
        id="pam_prompt_order_heuristic",
        description="PAM ordering likely prompts TOTP before password (heuristic)",
        passed=passed,
        details=details,
        severity="optional",
    ))

    has_access = bool(
        re.search(r"^\s*account\s+.*pam_access\.so\b", pam_text, re.M)
    )
    checks.append(CheckResult(
        id="pam_access_present",
        description="/etc/pam.d/sshd includes pam_access.so in account stack",
        passed=has_access,
        details=(
            "Found" if has_access
            else "Missing 'pam_access.so' in account stack"
        ),
    ))

    has_time = bool(re.search(r"^\s*account\s+.*pam_time\.so\b", pam_text, re.M))
    checks.append(CheckResult(
        id="pam_time_present",
        description=(
            "/etc/pam.d/sshd includes pam_time.so in account stack (optional)"
        ),
        passed=has_time,
        details="Found" if has_time else "Not configured (optional)",
        severity="optional",
    ))

    return checks


def audit_sshd_config(sshd_text: str) -> List[CheckResult]:
    """Audits sshd_config for MFA-enabling directives."""
    checks: List[CheckResult] = []

    def has_directive(key: str, expected: Optional[str] = None) -> Tuple[bool, str]:
        rx = re.compile(rf"^\s*{re.escape(key)}\s+(\S+)", re.I | re.M)
        m = rx.search(sshd_text)
        if not m:
            return False, f"Missing {key}"
        val = m.group(1)
        if expected is None:
            return True, f"{key} {val}"
        return (
            (val.lower() == expected.lower()),
            f"{key} {val} (expected {expected})"
        )

    ok, details = has_directive("UsePAM", "yes")
    checks.append(CheckResult(
        id="sshd_usepam_yes",
        description="sshd_config: UsePAM yes (required for PAM MFA)",
        passed=ok,
        details=details,
    ))

    # OpenSSH key name changed over time; accept either.
    kbdi_ok, kbdi_details = has_directive("KbdInteractiveAuthentication", "yes")
    cra_ok, cra_details = has_directive("ChallengeResponseAuthentication", "yes")
    passed = kbdi_ok or cra_ok
    details = f"{kbdi_details}; {cra_details}"
    checks.append(CheckResult(
        id="sshd_interactive_enabled",
        description=(
            "sshd_config: interactive auth enabled "
            "(KbdInteractive/ChallengeResponse)"
        ),
        passed=passed,
        details=details,
    ))

    # PasswordAuthentication may be optional if you use pubkey+TOTP only
    ok, details = has_directive("PasswordAuthentication", "yes")
    checks.append(CheckResult(
        id="sshd_passwordauth_yes",
        description="sshd_config: PasswordAuthentication yes (optional)",
        passed=ok,
        details=details,
        severity="optional",
    ))

    # AuthenticationMethods check (optional but recommended)
    rx_am = re.compile(r"^\s*AuthenticationMethods\s+(.+)$", re.I | re.M)
    m = rx_am.search(sshd_text)
    if not m:
        checks.append(CheckResult(
            id="sshd_authenticationmethods_present",
            description="sshd_config: AuthenticationMethods is set (recommended)",
            passed=False,
            details="Missing AuthenticationMethods directive",
            severity="optional",
        ))
    else:
        am = m.group(1).strip()
        needs_interactive = bool(
            re.search(r"keyboard-interactive|kbdinteractive", am, re.I)
        )
        checks.append(CheckResult(
            id="sshd_authenticationmethods_includes_interactive",
            description=(
                "sshd_config: AuthenticationMethods includes keyboard-interactive"
            ),
            passed=needs_interactive,
            details=f"AuthenticationMethods {am}",
            severity="optional",
        ))

    return checks


def audit_access_conf(
    access_text: str,
    expected_rules: Optional[int]
) -> List[CheckResult]:
    """Audits access.conf for rule presence and sanity."""
    checks: List[CheckResult] = []

    rules = []
    for line in access_text.splitlines():
        line_stripped = line.strip()
        if not line_stripped or line_stripped.startswith("#"):
            continue
        m = RE_RULE.match(line)
        if m:
            rules.append(m.group(1))

    rule_count = len(rules)
    allow_count = sum(1 for r in rules if r == "+")
    deny_count = sum(1 for r in rules if r == "-")

    checks.append(CheckResult(
        id="access_conf_has_rules",
        description="/etc/security/access.conf contains at least one rule",
        passed=rule_count > 0,
        details=f"rules={rule_count}, allow={allow_count}, deny={deny_count}",
    ))

    if expected_rules is not None:
        checks.append(CheckResult(
            id="access_conf_expected_rule_count",
            description=f"access.conf has expected rules ({expected_rules})",
            passed=(rule_count == expected_rules),
            details=f"rules={rule_count}",
            severity="optional",
        ))

    # Catch-all deny recommended
    last_rule_line = None
    for line in reversed(access_text.splitlines()):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        last_rule_line = s
        break

    passed = bool(
        last_rule_line and
        re.match(r"^-\s*:\s*ALL\s*:\s*ALL\s*$", last_rule_line, re.I)
    )
    checks.append(CheckResult(
        id="access_conf_catchall_deny_last",
        description="access.conf ends with catch-all deny (- : ALL : ALL)",
        passed=passed,
        details=f"last_rule={last_rule_line!r}",
        severity="optional",
    ))

    return checks


def main() -> int:
    """Main entry point for the audit script."""
    # Detect CI environment
    default_root = "/"
    if os.environ.get("GITHUB_ACTIONS") == "true":
        default_root = "./fixtures"

    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--root", default=default_root,
        help="Alternate root (for mounted images / fixtures)"
    )
    ap.add_argument(
        "--fixtures", dest="root",
        help="Alias for --root", required=False
    )
    ap.add_argument("--json", action="store_true", help="Emit JSON output")
    ap.add_argument(
        "--expected-access-rules", type=int, default=None,
        help="Optional expected rule count in access.conf"
    )
    args = ap.parse_args()

    paths = {
        "pam_sshd": join_root(args.root, "/etc/pam.d/sshd"),
        "sshd_config": join_root(args.root, "/etc/ssh/sshd_config"),
        "access_conf": join_root(args.root, "/etc/security/access.conf"),
    }

    results: List[CheckResult] = []
    missing: List[str] = []

    pam = read_text(paths["pam_sshd"])
    if pam is None:
        missing.append(paths["pam_sshd"])
    else:
        results.extend(audit_pam_sshd(pam))

    sshd = read_text(paths["sshd_config"])
    if sshd is None:
        missing.append(paths["sshd_config"])
    else:
        results.extend(audit_sshd_config(sshd))

    access = read_text(paths["access_conf"])
    if access is None:
        missing.append(paths["access_conf"])
    else:
        results.extend(audit_access_conf(access, args.expected_access_rules))

    required_failed = [r for r in results if r.severity == "required" and not r.passed]
    overall_pass = (len(missing) == 0 and len(required_failed) == 0)

    payload = {
        "overall": "PASS" if overall_pass else "FAIL",
        "missing_files": missing,
        "results": [r.__dict__ for r in results],
    }

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"Overall: {payload['overall']}")
        if missing:
            print("\nMissing files:")
            for p in missing:
                print(f"  - {p}")
        print("\nChecks:")
        for r in results:
            badge = "PASS" if r.passed else "FAIL"
            sev = "REQ" if r.severity == "required" else "OPT"
            print(f"  [{badge}] ({sev}) {r.id}: {r.description}")
            print(f"         {r.details}")
        print()

    return 0 if overall_pass else 2


if __name__ == "__main__":
    raise SystemExit(main())
