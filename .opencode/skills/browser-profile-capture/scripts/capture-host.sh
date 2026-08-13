#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'Usage: %s <interface> <duration-seconds> <output.pcapng> <capture-filter>\n' "$0" >&2
}

if (( $# != 4 )); then
  usage
  exit 64
fi

interface=$1
duration=$2
output=$3
capture_filter=$4

if ! command -v dumpcap >/dev/null 2>&1; then
  printf 'error: dumpcap is not installed or not on PATH\n' >&2
  exit 69
fi

if [[ ! $duration =~ ^[1-9][0-9]*$ ]]; then
  printf 'error: duration must be a positive integer in seconds\n' >&2
  exit 64
fi

if [[ -z $capture_filter ]]; then
  printf 'error: a narrow libpcap capture filter is required\n' >&2
  exit 64
fi

output_parent=$(dirname "$output")
if [[ ! -d $output_parent ]]; then
  printf 'error: output directory does not exist: %s\n' "$output_parent" >&2
  exit 72
fi

if [[ -e $output ]]; then
  printf 'error: refusing to overwrite existing capture: %s\n' "$output" >&2
  exit 73
fi

dumpcap \
  -i "$interface" \
  -f "$capture_filter" \
  --autostop "duration:$duration" \
  --capture-comment "authorized browser compatibility capture" \
  -w "$output"
