#!/usr/bin/env python3
"""validate_access_conf.py

Offline evaluator for a subset of pam_access rule semantics so you can test
an access policy against a CSV matrix without touching a live SSH server.

Supported:
- Rule format: (+/-) : users : origins
- users: ALL, exact usernames, @group tokens, user lists separated by whitespace
- origins: ALL, LOCAL, IPv4 net/mask (e.g., 10.8.0.0/255.255.255.0), IPv4 addresses
- EXCEPT (basic): 'ALL EXCEPT <token> <token>'

CSV matrix columns:
  user, groups, origin, expected
Where:
  groups = comma-separated group names (no leading @)
  origin = 'LOCAL' or an IPv4 address
  expected = ALLOW or DENY
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import re
import sys
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple


RE_RULE = re.compile(r"^\s*([+-])\s*:\s*(.*?)\s*:\s*(.*?)\s*$")


@dataclass
class Rule:
    action: str  # '+' or '-'
    users: str
    origins: str
    raw: str


def parse_tokens(expr: str) -> Tuple[List[str], List[str]]:
    """Return (include, exclude) tokens based on EXCEPT."""
    parts = expr.split()
    if not parts:
        return [], []
    if "EXCEPT" in parts:
        idx = parts.index("EXCEPT")
        inc = parts[:idx]
        exc = parts[idx + 1 :]
        return inc, exc
    return parts, []


def user_matches(rule_users: str, user: str, groups: List[str]) -> bool:
    inc, exc = parse_tokens(rule_users)

    def token_match(tok: str) -> bool:
        if tok == "ALL":
            return True
        if tok.startswith("@"):
            return tok[1:] in groups
        return tok == user

    if inc and not any(token_match(t) for t in inc):
        return False
    if exc and any(token_match(t) for t in exc):
        return False
    return True


def parse_net(tok: str) -> Optional[ipaddress.IPv4Network]:
    # Accept net/mask where mask may be dotted or prefix length.
    if "/" not in tok:
        return None
    net, mask = tok.split("/", 1)
    try:
        # prefix
        if mask.isdigit():
            return ipaddress.ip_network(f"{net}/{mask}", strict=False)
        # dotted netmask
        prefix = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
        return ipaddress.ip_network(f"{net}/{prefix}", strict=False)
    except Exception:
        return None


def origin_matches(rule_origins: str, origin: str) -> bool:
    inc, exc = parse_tokens(rule_origins)

    def token_match(tok: str) -> bool:
        if tok == "ALL":
            return True
        if tok == "LOCAL":
            return origin == "LOCAL"
        net = parse_net(tok)
        if net is not None:
            if origin == "LOCAL":
                return False
            try:
                ip = ipaddress.ip_address(origin)
                return ip in net
            except Exception:
                return False
        # exact host/ip match
        return tok == origin

    if inc and not any(token_match(t) for t in inc):
        return False
    if exc and any(token_match(t) for t in exc):
        return False
    return True


def load_rules(path: str) -> List[Rule]:
    rules: List[Rule] = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            m = RE_RULE.match(line)
            if not m:
                continue
            rules.append(Rule(action=m.group(1), users=m.group(2).strip(), origins=m.group(3).strip(), raw=s))
    return rules


def evaluate(rules: List[Rule], user: str, groups: List[str], origin: str) -> Optional[str]:
    for r in rules:
        if user_matches(r.users, user, groups) and origin_matches(r.origins, origin):
            return "ALLOW" if r.action == "+" else "DENY"
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--access-conf", required=True, help="Path to access.conf policy")
    ap.add_argument("--matrix", required=True, help="CSV test matrix path")
    args = ap.parse_args()

    rules = load_rules(args.access_conf)
    if not rules:
        print("[!] No parseable rules found.")
        return 2

    total = 0
    passed = 0
    failed_rows: List[str] = []

    with open(args.matrix, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            total += 1
            user = row["user"].strip()
            origin = row["origin"].strip()
            expected = row["expected"].strip().upper()
            groups = [g.strip() for g in row.get("groups", "").split(",") if g.strip()]
            got = evaluate(rules, user, groups, origin) or "NO_MATCH"
            ok = (got == expected)
            if ok:
                passed += 1
            else:
                failed_rows.append(f"row {total}: user={user} groups={groups} origin={origin} expected={expected} got={got}")

    print(f"Results: {passed}/{total} passed ({(passed/total*100):.1f}%)")
    if failed_rows:
        print("\nFailures:")
        for fr in failed_rows:
            print("  - " + fr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
