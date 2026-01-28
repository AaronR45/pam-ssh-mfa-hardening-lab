#!/usr/bin/env bash
set -euo pipefail

# Applies PAM SSH MFA + pam_access policy with backups.
# Tested for Debian/Kali/Ubuntu style layouts.

TS="$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="/var/backups/pam-ssh-mfa-hardening/${TS}"
FORCE=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Parse arguments
for arg in "$@"; do
  case $arg in
    --yes|-y)
      FORCE=1
      shift
      ;;
  esac
done

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    log_error "Run as root (sudo)."
    exit 1
  fi
}

confirm_action() {
  if [[ "$FORCE" -eq 1 ]]; then return; fi
  echo ""
  echo -e "${YELLOW}⚠️  WARNING: RISK OF SSH LOCKOUT ⚠️${NC}"
  echo ""
  echo "This script will modify SSH authentication configuration."
  echo "1. Ensure you have an open root shell in a separate terminal."
  echo "2. Ensure you have an out-of-band access method (console/VM)."
  echo "3. Read docs/LOCKOUT_RISK.md if unsure."
  echo ""
  read -p "Are you sure you want to proceed? [y/N] " -r
  echo
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    log_info "Aborted."
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

backup_file() {
  local f="$1"
  if [[ -f "$f" ]]; then
    mkdir -p "${BACKUP_DIR}"
    cp -a "$f" "${BACKUP_DIR}/"
    log_info "Backed up $f -> ${BACKUP_DIR}/"
  else
    log_info "Skipping backup (missing): $f"
  fi
}

rollback() {
  log_error "Validation failed! Rolling back changes..."
  if [[ -d "${BACKUP_DIR}" ]]; then
     cp -a "${BACKUP_DIR}/"sshd_config /etc/ssh/sshd_config 2>/dev/null || true
     cp -a "${BACKUP_DIR}/"sshd /etc/pam.d/sshd 2>/dev/null || true
     cp -a "${BACKUP_DIR}/"access.conf /etc/security/access.conf 2>/dev/null || true
     log_info "Rolled back files from ${BACKUP_DIR}"
  else
     log_error "No backup directory found at ${BACKUP_DIR}"
  fi
  exit 1
}

ensure_line_before_match() {
  # ensure_line_before_match <file> <line_to_ensure> <regex_anchor>
  local f="$1"
  local line="$2"
  local anchor="$3"

  if grep -Fqx "$line" "$f"; then
    return
  fi

  if grep -Eq "$anchor" "$f"; then
    # insert before first anchor match
    local tmp
    tmp="$(mktemp)"
    awk -v ins="$line" -v re="$anchor" '
      BEGIN{done=0}
      {
        if(!done && $0 ~ re){ print ins; done=1 }
        print
      }
      END{ if(!done) print ins }
    ' "$f" > "$tmp"
    cat "$tmp" > "$f"
    rm -f "$tmp"
  else
    echo "$line" >> "$f"
  fi
}

set_sshd_directive() {
  # set_sshd_directive <file> <Key> <Value>
  local f="$1"
  local key="$2"
  local val="$3"

  if grep -Eq "^[#\s]*${key}\b" "$f"; then
    # replace first occurrence (commented or not)
    sed -i -E "0,/^[#\s]*${key}\b.*/s//${key} ${val}/" "$f"
  else
    echo "${key} ${val}" >> "$f"
  fi
}

main() {
  need_root
  confirm_action

  # Preflight check: Ensure current config is valid before doing anything
  log_info "Preflight: validating current sshd config..."
  if ! sshd -t; then
    log_error "Current sshd config is invalid. Fix it before applying changes."
    exit 1
  fi

  # Dependencies: best-effort check
  if ! command -v google-authenticator >/dev/null 2>&1; then
    log_info "google-authenticator binary not found. Installing libpam-google-authenticator..."
    apt-get update -y
    apt-get install -y libpam-google-authenticator
  fi

  local PAM_SSHD="/etc/pam.d/sshd"
  local SSHD_CONF="/etc/ssh/sshd_config"
  local ACCESS_CONF="/etc/security/access.conf"

  backup_file "$PAM_SSHD"
  backup_file "$SSHD_CONF"
  backup_file "$ACCESS_CONF"

  # ---- PAM: enforce MFA and pam_access ----
  if [[ ! -f "$PAM_SSHD" ]]; then
    log_error "Missing $PAM_SSHD. Is openssh-server installed?"
    exit 1
  fi

  # Ensure TOTP line appears BEFORE common-auth include (prompt order: verification code then password)
  ensure_line_before_match "$PAM_SSHD" "auth required pam_google_authenticator.so" "^@include[[:space:]]+common-auth"

  # Ensure pam_access in account stack (before common-account include)
  ensure_line_before_match "$PAM_SSHD" "account required pam_access.so" "^@include[[:space:]]+common-account"

  # ---- access.conf policy ----
  if [[ ! -f "$ACCESS_CONF" ]]; then
    touch "$ACCESS_CONF"
    chmod 0644 "$ACCESS_CONF"
  fi

  # If file is empty (or only comments), seed with example policy block.
  if ! grep -Eq '^[[:space:]]*[+-][[:space:]]*:' "$ACCESS_CONF"; then
    cat >> "$ACCESS_CONF" <<'EOF'

# === Seeded by pam-ssh-mfa-hardening-lab ===
# Format: (+/-) : users : origins
# First match wins. Order is critical.
+ : @ssh_admins : 10.8.0.0/255.255.255.0
+ : @ssh_admins : 172.16.10.0/255.255.255.0
+ : @ssh_admins : LOCAL
- : @ssh_admins : ALL

+ : @ssh_engineering : 10.8.0.0/255.255.255.0
+ : @ssh_engineering : 192.168.64.0/255.255.255.0
+ : @ssh_engineering : 10.20.0.0/255.255.0.0
- : @ssh_engineering : ALL

+ : @ssh_students : 10.20.0.0/255.255.0.0
+ : @ssh_students : 192.168.64.0/255.255.255.0
- : @ssh_students : ALL

+ : @ssh_service : 192.168.10.0/255.255.255.0
+ : @ssh_service : 172.16.10.0/255.255.255.0
- : @ssh_service : ALL

+ : root : LOCAL
+ : root : 10.8.0.0/255.255.255.0
- : root : ALL

- : ALL : ALL
# === End seeded block ===
EOF
    log_success "Seeded $ACCESS_CONF with example policy block."
  else
    log_info "$ACCESS_CONF already has rules; leaving as-is."
  fi

  # ---- sshd_config ----
  if [[ ! -f "$SSHD_CONF" ]]; then
    log_error "Missing $SSHD_CONF. Is openssh-server installed?"
    exit 1
  fi

  set_sshd_directive "$SSHD_CONF" "UsePAM" "yes"
  set_sshd_directive "$SSHD_CONF" "KbdInteractiveAuthentication" "yes"
  set_sshd_directive "$SSHD_CONF" "ChallengeResponseAuthentication" "yes"
  set_sshd_directive "$SSHD_CONF" "PasswordAuthentication" "yes"

  # Set AuthenticationMethods (add if absent).
  # This is a lab-friendly example; tune for your real policy.
  if ! grep -Eq "^[#\s]*AuthenticationMethods\b" "$SSHD_CONF"; then
    echo "AuthenticationMethods publickey,password publickey,keyboard-interactive" >> "$SSHD_CONF"
  fi

  # Validate config
  log_info "Validating sshd config..."
  if ! sshd -t; then
     rollback
  fi

  # Restart ssh
  local svc
  svc="$(detect_service)"
  log_info "Restarting ${svc}..."
  if command -v systemctl >/dev/null 2>&1; then
    systemctl restart "${svc}"
    systemctl --no-pager status "${svc}" || true
  else
    service "${svc}" restart || true
  fi

  echo
  log_success "Applied. Backups: ${BACKUP_DIR}"
  log_success "Next: run audit -> sudo ./scripts/audit_pam_ssh_mfa.py"
}

main "$@"
