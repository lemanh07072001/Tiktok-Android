
void FUN_0019b388(undefined8 param_1,undefined8 param_2,undefined8 param_3)

{
  long lVar1;
  undefined8 local_328;
  undefined8 uStack_320;
  undefined8 local_318;
  code *pcStack_310;
  undefined1 *local_308;
  undefined1 auStack_30 [8];
  long local_28;
  
  lVar1 = tpidr_el0;
  local_28 = *(long *)(lVar1 + 0x28);
  local_308 = auStack_30;
  pcStack_310 = FUN_0019b414;
  local_328 = param_1;
  uStack_320 = param_2;
  local_318 = param_3;
  FUN_00152924(&DAT_00286480,&local_328,0,0,&pcStack_310);
  if (*(long *)(lVar1 + 0x28) == local_28) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

