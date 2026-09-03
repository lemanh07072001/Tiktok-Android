
void FUN_00195a3c(undefined8 param_1)

{
  long lVar1;
  undefined8 local_1308;
  code *pcStack_1300;
  undefined1 *local_12f8;
  undefined1 auStack_30 [8];
  long local_28;
  
  lVar1 = tpidr_el0;
  local_28 = *(long *)(lVar1 + 0x28);
  pcStack_1300 = FUN_0019b414;
  local_12f8 = auStack_30;
  local_1308 = param_1;
  FUN_00152924(&DAT_002814f0,&local_1308,&DAT_002db360,&DAT_002db430,&pcStack_1300);
  if (*(long *)(lVar1 + 0x28) == local_28) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

