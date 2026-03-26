#!/bin/bash

set -e

SCRIPT_DIR="$(cd -- "$(dirname "$0")" >/dev/null 2>&1; pwd -P)"

cd "$SCRIPT_DIR/../build"

meson test --timeout-multiplier=0 --print-errorlogs
