#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -eq 0 ]]; then
  echo "at least one Ubuntu package is required" >&2
  exit 2
fi

readonly mirror_list=/etc/apt/apt-mirrors.txt
if [[ -f "$mirror_list" ]]; then
  printf '%s\n' 'https://archive.ubuntu.com/ubuntu' | sudo tee "$mirror_list" >/dev/null
fi

apt_with_retry() {
  local attempt
  for attempt in 1 2 3; do
    if sudo timeout 180 apt-get \
      -o Acquire::Retries=2 \
      -o Acquire::http::Timeout=15 \
      -o Acquire::https::Timeout=15 \
      "$@"; then
      return 0
    fi
    if [[ "$attempt" -eq 3 ]]; then
      echo "apt command failed after 3 bounded attempts" >&2
      return 1
    fi
    sleep "$((attempt * 5))"
  done
}

apt_with_retry update
apt_with_retry install -y --no-install-recommends "$@"
