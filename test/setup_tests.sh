#!/bin/bash 
set -euxo pipefail
TEST_DIR=$(pwd)
export TEST_DIR

# apparently github actions do not define TMPDIR
TMPDIR=${TMPDIR:-/tmp}
export TMPDIR

# if GHIDRA_HOME is set, use it; otherwise set one up
if [ -z "${GHIDRA_HOME:-}" ]; then
    GHIDRA_HOME="$TMPDIR/ghidra_STM8_tests/ghidra_home"
    export GHIDRA_HOME
fi

analyzeHeadless="$GHIDRA_HOME/support/analyzeHeadless"

# if analyzeHeadless exists, use it; otherwise we need to install ghidra
if [ ! -e "$analyzeHeadless" ]; then
    # first download the zip if it isn't there already
    ghidra_zip="$TMPDIR/ghidra.zip"
    ghidra_url="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.4.2_build/ghidra_11.4.2_PUBLIC_20250826.zip"
    if [ ! -e "ghidra_zip" ]; then
        curl --silent -L "$ghidra_url" --output "$ghidra_zip" 1>&2
    fi

    mkdir -p "$GHIDRA_HOME";
    cd "$GHIDRA_HOME";
    unzip -qq "$ghidra_zip" 1>&2;
    # the ghidra zip file adds an extra directory layer; remove it
    extra_dir="$(ls)"
    (shopt -s dotglob; mv "$extra_dir"/* .)
    rmdir "$extra_dir"
fi

# install extension with a symlink
extensions_dir="$GHIDRA_HOME/Ghidra/Extensions"
rmdir "$extensions_dir"
ln -sf "$TEST_DIR/.." "$extensions_dir"

# ensure sdcc enabled
if ! which sdcc; then
    sudo apt install -y sdcc 1>&2
fi

echo "GHIDRA_HOME=$GHIDRA_HOME"
echo "TEST_DIR=$TEST_DIR"
