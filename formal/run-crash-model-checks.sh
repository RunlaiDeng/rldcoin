#!/usr/bin/env bash
set -euo pipefail

formal_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
tool_dir=${TLC_CACHE_DIR:-"$formal_dir/.tools"}
out_dir=${TLC_OUTPUT_DIR:-"$formal_dir/out"}
tlc_version=1.7.4
tlc_url="https://github.com/tlaplus/tlaplus/releases/download/v${tlc_version}/tla2tools.jar"
tlc_sha1=bee4a54f3ee3d4afc347c3240ec2d9e93b075104
tlc_sha256=936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88
tlc_jar="$tool_dir/tla2tools-${tlc_version}.jar"
active_state_dir=""

mkdir -p "$tool_dir" "$out_dir"

cleanup_active_state_dir() {
  if [[ -n "$active_state_dir" && -d "$active_state_dir" ]]; then
    case "$active_state_dir" in
      "$out_dir"/.tlc-crash-*) find "$active_state_dir" -depth -delete ;;
      *)
        printf 'Refusing to remove unexpected TLC state path: %s\n' "$active_state_dir" >&2
        return 2
        ;;
    esac
  fi
  active_state_dir=""
}

trap cleanup_active_state_dir EXIT INT TERM

verify_tlc() {
  local actual_sha1 actual_sha256
  actual_sha1=$(shasum "$tlc_jar" | awk '{print $1}')
  actual_sha256=$(shasum -a 256 "$tlc_jar" | awk '{print $1}')
  if [[ "$actual_sha1" != "$tlc_sha1" || "$actual_sha256" != "$tlc_sha256" ]]; then
    printf 'TLC checksum mismatch: %s\n' "$tlc_jar" >&2
    printf 'Expected SHA-1:   %s\nActual SHA-1:     %s\n' "$tlc_sha1" "$actual_sha1" >&2
    printf 'Expected SHA-256: %s\nActual SHA-256:   %s\n' "$tlc_sha256" "$actual_sha256" >&2
    exit 2
  fi
}

if [[ ! -f "$tlc_jar" ]]; then
  download_path="$tlc_jar.download"
  printf 'Downloading TLC %s from %s\n' "$tlc_version" "$tlc_url"
  curl --fail --location --retry 3 --connect-timeout 20 "$tlc_url" --output "$download_path"
  mv "$download_path" "$tlc_jar"
fi
verify_tlc

run_check() {
  local name=$1
  local config=$2
  local expectation=$3
  local expected_invariant=${4:-}
  local log="$out_dir/crash-$name.log"
  local status

  printf '\n=== crash/%s (%s) ===\n' "$name" "$expectation"
  active_state_dir=$(mktemp -d "$out_dir/.tlc-crash-${name}.XXXXXX")
  set +e
  (
    cd "$formal_dir"
    java -XX:+UseParallelGC -Xmx2g -jar "$tlc_jar" \
      -workers 1 \
      -seed 20260903 \
      -fp 0 \
      -deadlock \
      -metadir "$active_state_dir" \
      -config "$config" \
      RldcoinCrashConsistency.tla
  ) 2>&1 | tee "$log"
  status=${PIPESTATUS[0]}
  set -e
  cleanup_active_state_dir

  if [[ "$expectation" == "pass" ]]; then
    if [[ $status -ne 0 ]] || ! grep -Fq "Model checking completed. No error has been found." "$log"; then
      printf 'Safe crash model did not pass: %s (status %s)\n' "$name" "$status" >&2
      exit 1
    fi
  else
    if [[ $status -eq 0 ]]; then
      printf 'Crash counterexample unexpectedly passed: %s\n' "$name" >&2
      exit 1
    fi
    if ! grep -Fq "Invariant ${expected_invariant} is violated." "$log"; then
      printf 'Crash counterexample failed, but not on expected invariant %s: %s\n' \
        "$expected_invariant" "$name" >&2
      exit 1
    fi
  fi
}

run_safe() {
  run_check safe config/crash/safe.cfg pass
}

run_counterexamples() {
  run_check sign-before-lock \
    config/crash/counterexamples/sign-before-lock.cfg fail NoHonestDoubleVote
  run_check partial-wal-ignored \
    config/crash/counterexamples/partial-wal-ignored.cfg fail CorruptWalFailsClosed
  run_check anchor-rollback \
    config/crash/counterexamples/anchor-rollback.cfg fail AnchorNeverRollsBack
  run_check checkpoint-overwrites-wal \
    config/crash/counterexamples/checkpoint-overwrites-wal.cfg fail CheckpointFailurePreservesCommittedWal
  run_check vote-lock-lost-on-recovery \
    config/crash/counterexamples/vote-lock-lost-on-recovery.cfg fail NoHonestDoubleVote
  run_check whole-directory-rollback \
    config/crash/counterexamples/whole-directory-rollback.cfg fail WholeDirectoryRollbackNeedsExternalWitness
}

case "${1:-all}" in
  safe) run_safe ;;
  counterexamples) run_counterexamples ;;
  all)
    run_safe
    run_counterexamples
    ;;
  *)
    printf 'Usage: %s [safe|counterexamples|all]\n' "$0" >&2
    exit 2
    ;;
esac

printf '\nAll requested crash-model runs matched expected outcomes. Logs: %s\n' "$out_dir"

