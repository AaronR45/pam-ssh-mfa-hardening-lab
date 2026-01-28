#!/usr/bin/env bash
set -euo pipefail

# Restores backed up configs from /var/backups/pam-ssh-mfa-hardening/<timestamp>/

BASE="/var/backups/pam-ssh-mfa-hardening"

usage() {
  echo "Usage:"
  echo "  sudo ./scripts/rollback.sh --latest"
  echo "  sudo ./scripts/rollback.sh --ts <YYYYMMDD_HHMMSS>"
}

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "[!] Run as root (sudo)." >&2
    exit 1
  fi
}

detect_service() {
  if command -v systemctl >/dev/null 2>&1; then
    if systemctl list-units --type=service | grep -qE '(^|\s)ssh\.service'; then
      echo "ssh"
      return
    fi
    if systemctl list-units --type=service | grep -qE '(^|\s)sshd\.service'; then
      echo "sshd"
      return
    fi
  fi
  echo "ssh"
}

restore_from_dir() {
  local d="$1"
  [[ -d "$d" ]] || { echo "[!] Backup dir not found: $d" >&2; exit 1; }

  if [[ -f "${d}/sshd_config" ]]; then
    cp -a "${d}/sshd_config" /etc/ssh/sshd_config
    echo "[+] Restored /etc/ssh/sshd_config"
  fi
  if [[ -f "${d}/sshd" ]]; then
    cp -a "${d}/sshd" /etc/pam.d/sshd
    echo "[+] Restored /etc/pam.d/sshd"
  fi
  if [[ -f "${d}/access.conf" ]]; then
    cp -a "${d}/access.conf" /etc/security/access.conf
    echo "[+] Restored /etc/security/access.conf"
  fi
  if [[ -f "${d}/time.conf" ]]; then
    cp -a "${d}/time.conf" /etc/security/time.conf
    echo "[+] Restored /etc/security/time.conf"
  fi

  # Validate config before restart
  echo "[i] Validating restored sshd config..."
  if ! sshd -t; then
    echo "[!] WARNING: Restored config failed validation!"
    echo "[!] Leaving files in place but NOT restarting SSH service."
    exit 1
  fi

  local svc
  svc="$(detect_service)"
  echo "[+] Restarting ${svc}..."
  if command -v systemctl >/dev/null 2>&1; then
    systemctl restart "${svc}"
    systemctl --no-pager status "${svc}" || true
  else
    service "${svc}" restart || true
  fi
  echo "[✓] Rollback complete."
}

main() {
  need_root

  if [[ $# -lt 1 ]]; then usage; exit 1; fi

  if [[ "$1" == "--latest" ]]; then
    local latest
    latest="$(ls -1 "${BASE}" 2>/dev/null | sort | tail -n 1 || true)"
    [[ -n "$latest" ]] || { echo "[!] No backups found in ${BASE}" >&2; exit 1; }
    restore_from_dir "${BASE}/${latest}"
    exit 0
  fi

  if [[ "$1" == "--ts" && $# -ge 2 ]]; then
    restore_from_dir "${BASE}/$2"
    exit 0
  fi

  usage
  exit 1
}

main "$@"
