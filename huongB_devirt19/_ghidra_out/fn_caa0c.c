
void FUN_001caa0c(undefined8 param_1,undefined8 param_2)

{
  long lVar1;
  undefined1 auStack_48 [16];
  undefined1 auStack_38 [4];
  int local_34;
  long local_28;
  
  lVar1 = tpidr_el0;
  local_28 = *(long *)(lVar1 + 0x28);
  FUN_0024fc68(auStack_48,param_2);
  FUN_001891f4(auStack_38,auStack_48);
  FUN_0024fe34(auStack_48);
  FUN_0024fa94(param_1);
  if (0 < local_34) {
    FUN_0020b940(auStack_48,auStack_38);
    FUN_0025009c(param_1,auStack_48);
    FUN_0024fe34(auStack_48);
  }
  FUN_0024fe34(auStack_38);
  if (*(long *)(lVar1 + 0x28) == local_28) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

