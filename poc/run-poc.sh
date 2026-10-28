#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -r "$work"' EXIT
for name in path_escape_poc full_chain_poc differential; do
  g++ -std=c++17 "$here/$name.cc" -o "$work/$name"
done
"$work/path_escape_poc"
echo
(cd "$work" && ./full_chain_poc)
echo
"$work/differential"
