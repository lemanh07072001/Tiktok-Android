
void FUN_001d9948(long param_1,long param_2)

{
  long lVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int iVar4;
  undefined1 auStack_48 [16];
  long local_38;
  
  lVar1 = tpidr_el0;
  local_38 = *(long *)(lVar1 + 0x28);
  if (*(int *)(param_2 + 4) != 0) {
    FUN_0015f584(auStack_48,*(undefined8 *)(param_1 + 8));
    if (((DAT_002f4020 & 1) == 0) && (iVar4 = __cxa_guard_acquire(&DAT_002f4020), iVar4 != 0)) {
      DAT_002f4014 = 0xfff0bdc1;
      DAT_002f4000 = 0;
      DAT_002f4008 = 0;
      DAT_002f3ff8 = &PTR_FUN_002d9c90;
      DAT_002f4010 = 0;
      DAT_002f4018 = DAT_002f4014;
      __cxa_guard_release(&DAT_002f4020);
    }
    uVar2 = FUN_001611ec(*(undefined8 *)(param_1 + 8));
    uVar3 = FUN_0015f65c(*(undefined8 *)(param_1 + 8));
    iVar4 = FUN_002341a8(&DAT_002f3ff8,auStack_48,uVar2,uVar3);
    if ((iVar4 < 5) && (*(int *)(param_1 + 0xbc) == 0)) {
      (*(code *)(DAT_002f28d8 + -0x711a90))(param_1,param_2);
    }
    FUN_0024fe34(auStack_48);
  }
  if (*(long *)(lVar1 + 0x28) == local_38) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

