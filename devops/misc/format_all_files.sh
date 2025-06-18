#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

src_root="$PWD"

# ========== conf ==========
declare -a paths=(
    "networklib"
    "client"
    "server"
    "tests"
)

# check clang-format
if ! command -v clang-format &> /dev/null; then
    echo "Error: clang-format don't exist" >&2
    exit 1
fi

# ========== main ==========
for path in "${paths[@]}"; do
    dir="${src_root}/${path}"
    if [[ -d "$dir" ]]; then
        find "$dir" -type f \( -name "*.cpp" -o -name "*.c" -o -name "*.h" -o -name "*.hpp" \) -print0 | while IFS= read -r -d '' file; do
            echo "$file"
            clang-format -i -style=file "$file"
        done
    else
        echo "Warning: dir '$dir' don't exist"
    fi
done