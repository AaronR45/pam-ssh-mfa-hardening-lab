#!/usr/bin/env python3
"""generate_test_matrix.py

Generate a simple CSV allow/deny matrix for access.conf evaluation.

Usage:
  python3 scripts/generate_test_matrix.py --out tests/test_matrix.csv
"""

from __future__ import annotations

import argparse
import csv


DEFAULT_CASES = [
  # user, groups, origin, expected
  ("admin1", "ssh_admins", "10.8.0.10", "ALLOW"),
  ("admin1", "ssh_admins", "172.16.10.10", "ALLOW"),
  ("admin1", "ssh_admins", "192.168.64.10", "DENY"),

  ("admin2", "ssh_admins", "10.8.0.11", "ALLOW"),
  ("admin2", "ssh_admins", "172.16.10.11", "ALLOW"),
  ("admin2", "ssh_admins", "10.20.1.10", "DENY"),

  ("eng1", "ssh_engineering", "10.8.0.20", "ALLOW"),
  ("eng1", "ssh_engineering", "192.168.64.20", "ALLOW"),
  ("eng1", "ssh_engineering", "192.168.10.20", "DENY"),

  ("eng2", "ssh_engineering", "10.20.2.20", "ALLOW"),
  ("eng2", "ssh_engineering", "192.168.64.21", "ALLOW"),
  ("eng2", "ssh_engineering", "172.16.10.20", "DENY"),

  ("student1", "ssh_students", "10.20.3.10", "ALLOW"),
  ("student1", "ssh_students", "192.168.64.30", "ALLOW"),
  ("student1", "ssh_students", "10.8.0.30", "DENY"),

  ("student2", "ssh_students", "10.20.4.10", "ALLOW"),
  ("student2", "ssh_students", "192.168.64.31", "ALLOW"),
  ("student2", "ssh_students", "172.16.10.30", "DENY"),

  ("svc1", "ssh_service", "192.168.10.50", "ALLOW"),
  ("svc1", "ssh_service", "172.16.10.50", "ALLOW"),
  ("svc1", "ssh_service", "10.20.5.50", "DENY"),

  ("svc2", "ssh_service", "192.168.10.51", "ALLOW"),
  ("svc2", "ssh_service", "172.16.10.51", "ALLOW"),
  ("svc2", "ssh_service", "192.168.64.51", "DENY"),
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, help="Output CSV path")
    args = ap.parse_args()

    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["user", "groups", "origin", "expected"])
        for user, groups, origin, expected in DEFAULT_CASES:
            w.writerow([user, groups, origin, expected])

    print(f"Wrote {len(DEFAULT_CASES)} cases -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
