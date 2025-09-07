#!/bin/bash 
set -euxo pipefail

TEST_DIR="$(pwd)"
export TEST_DIR

# start with preamble patching up types
cat preamble.h > test_prog.c
# remove indented comment-only lines
# remove trailing comments
sed '/^ *\/\//d; s@//.*@@;' round_trip.c > expected_decompilation.c
# remove leading underscore from identifiers
sed 's/\([) ]\)_/\1/g' expected_decompilation.c >> test_prog.c

sdcc -mstm8 test_prog.c --out-fmt-elf \
     --nogcse --noinvariant --noinduction --noloopreverse \
     --no-peep




# create decompiled.c with the decompiled functions
rm -rf testProject.rep testProject.gpr
"$GHIDRA_HOME/support/analyzeHeadless" \
    "$TEST_DIR" testProject \
    -import test_prog.elf  -processor "STM8:BE:16:default" \
    -scriptPath "$TEST_DIR" -postScript 'DecompileHeadless.java'


# skip the first lines containing the static initializer and _main stub, then
# diff with original c code
sed -ne '/s_INITIALIZER/,$ p' decompiled.c | diff -Naur expected_decompilation.c -

echo "#### opcodes covered:"; cat test_prog.lst | grep -v '[;:]' | cut -c 14-30,42-|grep -v '^ .*\.' | sort -u 
