#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source_dir="${script_dir}/../skills/keyclasp-agent"
codex_home="${CODEX_HOME:-${HOME}/.codex}"
destination="${codex_home}/skills/keyclasp-agent"
skills_dir="${codex_home}/skills"
lock_dir="${skills_dir}/.keyclasp-agent.install.lock"

if [[ ! -d "${source_dir}" ]]; then
  echo "Keyclasp Codex skill not found at ${source_dir}" >&2
  exit 1
fi

mkdir -p -- "${skills_dir}"
lock_acquired=false
for _ in {1..100}; do
  if mkdir -- "${lock_dir}" 2>/dev/null; then
    lock_acquired=true
    break
  fi
  sleep 0.05
done

if [[ "${lock_acquired}" != true ]]; then
  echo "Another Keyclasp Codex skill installation is still running" >&2
  exit 1
fi

staging_dir=""
cleanup() {
  if [[ -n "${staging_dir}" ]]; then
    rm -rf -- "${staging_dir}"
  fi
  rmdir -- "${lock_dir}" 2>/dev/null || true
}
trap cleanup EXIT

staging_dir="$(mktemp -d "${skills_dir}/.keyclasp-agent.XXXXXX")"
backup_dir="${staging_dir}/previous"

mkdir -- "${staging_dir}/next"
cp -R -- "${source_dir}/." "${staging_dir}/next/"

if [[ -e "${destination}" ]]; then
  mv -- "${destination}" "${backup_dir}"
fi

if ! mv -- "${staging_dir}/next" "${destination}"; then
  if [[ -e "${backup_dir}" ]]; then
    mv -- "${backup_dir}" "${destination}"
  fi
  exit 1
fi

echo "Installed the Keyclasp Codex skill at ${destination}"
