#!/usr/bin/env bash

set -euo pipefail

build_type="release"
use_conan="ON"
with_tests="OFF"

print_help() {
  cat <<'EOF'
Usage: ./compile.sh [options]

Options:
  -d, --debug       Build with the Debug workflow preset
  -r, --release     Build with the Release workflow preset
  --no-conan        Use local dependencies instead of Conan
  --with-tests      Enable test targets
  -h, --help        Show this help

Examples:
  ./compile.sh
  ./compile.sh -d
  ./compile.sh --no-conan
  ./compile.sh -d --no-conan --with-tests
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    -d|--debug)
      build_type="debug"
      ;;
    -r|--release)
      build_type="release"
      ;;
    --no-conan)
      use_conan="OFF"
      ;;
    --with-tests)
      with_tests="ON"
      ;;
    -h|--help)
      print_help
      exit 0
      ;;
    *)
      echo "Unknown arg: $1" >&2
      print_help
      exit 1
      ;;
  esac
  shift
done

workflow_preset="${build_type}"

if [[ "${use_conan}" == "OFF" ]]; then
  workflow_preset="${workflow_preset}-noconan"
fi

if [[ "${with_tests}" == "ON" ]]; then
  workflow_preset="${workflow_preset}-tests"
fi

echo "Running CMake workflow preset: ${workflow_preset}"
cmake --workflow --preset "${workflow_preset}"
