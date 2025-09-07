// Variable names are chosen to collide with what the decompiler will choose for
// them in most cases. other patchups to make ghidra's decompilation output
// compile successfully are handled in test_prog.h .
undefined2 s_INITIALIZER(void)

{
  return 0x7b;
}


code * _get_fptr(void)

{
  return s_INITIALIZER;
}


undefined1 _get_char(void)

{
  return 1;
}


undefined2 _test_callx(void)

{
  code *pcVar1;
  
  pcVar1 = (code *)_get_fptr();
  (*pcVar1)();
  return 1;
}


void _test_jpx(void)

{
  code *UNRECOVERED_JUMPTABLE;
  
  UNRECOVERED_JUMPTABLE = (code *)_get_fptr();
                    /* WARNING: Could not recover jumptable at 0x8039. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*UNRECOVERED_JUMPTABLE)();
  return;
}


undefined1 _test_tnz(void)

{
  char cVar1;
  undefined1 uVar2;
  
  cVar1 = _get_char();
  if (cVar1 == '\0') {
    uVar2 = 0x10;
  }
  else {
    uVar2 = 0x11;
  }
  return uVar2;
}


undefined2 _main(undefined2 param_1)

{
  _test_jpx();
  _test_callx();
  _test_tnz();
  return param_1;
}

