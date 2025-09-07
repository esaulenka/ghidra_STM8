function compile_and_decompile {
    rm -rf test_prog.*
    cat > test_prog.c
    sdcc -mstm8 test_prog.c --out-fmt-elf

    # skip over the boilerplate and just show the code
    sed -ne '/test_prog.c/, $ p' test_prog.lst
    
    rm -rf testProject.rep testProject.gpr
    "$GHIDRA_HOME/support/analyzeHeadless" \
        "$TEST_DIR" testProject \
        -import test_prog.elf  -processor "STM8:BE:16:default" \
        -scriptPath "$TEST_DIR" -postScript 'DecompileHeadless.java'
}
