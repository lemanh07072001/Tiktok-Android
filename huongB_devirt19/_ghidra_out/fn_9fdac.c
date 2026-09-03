
void FUN_0019fd98(undefined8 param_1,undefined4 param_2,undefined8 param_3)

{
  long lVar1;
  long extraout_x8;
  undefined1 auStack_15e0 [5280];
  undefined1 auStack_140 [232];
  long local_58;
  
  lVar1 = tpidr_el0;
  local_58 = *(long *)(lVar1 + 0x28);
  (*(code *)(DAT_002f1280 + -0xe83eb0))(auStack_140);
  FUN_001a0fd4(DAT_002f1288,0xc);
  (*(code *)(extraout_x8 + -0xe83eb0))(auStack_15e0,param_1,param_2);
  (*(code *)(DAT_002f1290 + -0xe83eb0))(auStack_15e0,param_3);
  if (*(long *)(lVar1 + 0x28) == local_58) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

