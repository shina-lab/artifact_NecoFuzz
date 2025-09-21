#!/bin/bash
set -eu

if [[ -z "${XEN_GRUB_ENTRY:-}" ]]; then
    echo "[ERROR] XEN_GRUB_ENTRY is not set. Please export it or set in crontab."
    exit 1
fi

GRUB_ENTRY="$XEN_GRUB_ENTRY"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"

RETRY_FILE=/var/tmp/xen_retries
STOP_FILE=/var/tmp/xen_stop
MAX_RETRIES=3

# 停止フラグチェック
if [ -f "$STOP_FILE" ]; then
    echo "[INFO] Stop flag found ($STOP_FILE), exiting..."
    exit 0
fi

retries=$(cat "$RETRY_FILE" 2>/dev/null || echo 0)

if sudo xl info >/dev/null 2>&1; then
    echo "[INFO] Xen detected, starting NecoFuzz..."
    echo 0 > "$RETRY_FILE"
else
    retries=$((retries + 1))
    echo $retries > "$RETRY_FILE"
    if [ "$retries" -ge "$MAX_RETRIES" ]; then
        echo "[ERROR] Xen boot failed $MAX_RETRIES times, stopping."
        exit 1
    fi
    echo "[WARN] Xen not running (retry $retries/$MAX_RETRIES), rebooting into Xen..."
    sudo grub-reboot "$GRUB_ENTRY"
    sudo reboot
    exit 0
fi

cd $SCRIPT_DIR/../
seed="$(od -An -N4 -tu4 /dev/urandom | tr -d ' ')"
echo "[INFO] Using AFL_SEED=$seed"
sudo -n ./tools/scripts/afl-runner.sh -s "$seed"
