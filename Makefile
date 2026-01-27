SHELL := /bin/bash

.PHONY: audit audit-json validate-matrix

audit:
	sudo ./scripts/audit_pam_ssh_mfa.py

audit-json:
	sudo ./scripts/audit_pam_ssh_mfa.py --json

validate-matrix:
	python3 ./scripts/validate_access_conf.py --access-conf ./config/access.conf.example --matrix ./tests/test_matrix.csv
