#!/bin/sh
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export PATH="$project_dir/tools/macos-toolchain:$PATH"
cd "$project_dir"
if [ "$#" -eq 0 ]; then
    set -- build --release --workspace --locked
fi
exec cargo "$@"
