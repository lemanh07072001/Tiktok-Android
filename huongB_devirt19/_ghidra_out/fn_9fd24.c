
void FUN_0019fd18(undefined8 param_1,undefined8 param_2)

{
  long lVar1;
  undefined8 local_3f0;
  undefined8 uStack_3e8;
  code *local_3e0;
  undefined1 *puStack_3d8;
  undefined1 auStack_30 [8];
  long local_28;
  
  lVar1 = tpidr_el0;
  local_28 = *(long *)(lVar1 + 0x28);
  puStack_3d8 = auStack_30;
  local_3e0 = FUN_001a103c;
  local_3f0 = param_1;
  uStack_3e8 = param_2;
  FUN_00152924(&DAT_002864f0,&local_3f0,&DAT_002db7e8,&DAT_002db7f0,&local_3e0);
  if (*(long *)(lVar1 + 0x28) == local_28) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

