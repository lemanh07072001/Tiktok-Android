
void FUN_002349ac(long param_1)

{
  long lVar1;
  long lVar2;
  int iVar3;
  undefined8 uVar4;
  undefined1 auStack_68 [16];
  undefined1 auStack_58 [4];
  int local_54;
  long local_48;
  
  lVar2 = tpidr_el0;
  local_48 = *(long *)(lVar2 + 0x28);
  _ZNSt6__ndk119__shared_mutex_baseC1Ev();
  lVar1 = param_1 + 0x90;
  FUN_0024fa94(lVar1);
  FUN_0024fa94(param_1 + 0xa0);
  uVar4 = FUN_002185d0();
  FUN_0024fc68(auStack_68,PTR_s_rdk2_ms_002f3328);
  FUN_00217e94(auStack_58,uVar4,auStack_68);
  FUN_0025009c(param_1 + 0xa0,auStack_58);
  FUN_0024fe34(auStack_58);
  FUN_0024fe34(auStack_68);
  FUN_0024fc68(auStack_68,PTR_s_rtk2_ms_002f3330);
  FUN_00217e94(auStack_58,uVar4,auStack_68);
  FUN_0024fe34(auStack_68);
  if (local_54 < 1) {
    FUN_0024ff40(lVar1,&DAT_0029bb7e);
  }
  else {
    FUN_001891f4(auStack_68,auStack_58);
    FUN_0025009c(lVar1,auStack_68);
    FUN_0024fe34(auStack_68);
  }
  FUN_0024fc68(auStack_68,PTR_s_rsk2_ms_002f3338);
  iVar3 = FUN_00217fd0(uVar4,auStack_68);
  FUN_0024fe34(auStack_68);
  if (iVar3 < 2) {
    iVar3 = 1;
  }
  *(int *)(param_1 + 0xb0) = iVar3;
  FUN_0024fe34(auStack_58);
  if (*(long *)(lVar2 + 0x28) == local_48) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

