
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_0015f044(long param_1)

{
  long lVar1;
  long lVar2;
  int iVar3;
  undefined8 uVar4;
  ulong uVar5;
  long lVar6;
  long lVar7;
  undefined1 auStack_58 [16];
  long local_48;
  
  lVar2 = tpidr_el0;
  local_48 = *(long *)(lVar2 + 0x28);
  uVar4 = FUN_00219314();
  FUN_0024fc68(auStack_58,uVar4);
  lVar7 = *(long *)(param_1 + 0x108);
  param_1 = param_1 + 0x108;
  lVar6 = param_1;
  if (lVar7 != 0) {
    do {
      uVar5 = FUN_002506ec(lVar7 + 0x20,auStack_58);
      lVar1 = 8;
      if ((uVar5 & 1) == 0) {
        lVar1 = 0;
        lVar6 = lVar7;
      }
      lVar7 = *(long *)(lVar7 + lVar1);
    } while (lVar7 != 0);
    if ((lVar6 != param_1) && (uVar5 = FUN_002506ec(auStack_58,lVar6 + 0x20), (uVar5 & 1) == 0))
    goto LAB_0015f0cc;
  }
  lVar6 = param_1;
LAB_0015f0cc:
  FUN_0024fe34(auStack_58);
  if (lVar6 != param_1) {
    if (((DAT_002f3fc0 & 1) == 0) && (iVar3 = __cxa_guard_acquire(&DAT_002f3fc0), iVar3 != 0)) {
      DAT_002f3fb8 = 0;
      uRam00000000002f3fa0 = 0;
      _DAT_002f3f98 = 0;
      uRam00000000002f3fb0 = 0;
      _DAT_002f3fa8 = 0;
      uRam00000000002f3f90 = 0;
      _DAT_002f3f88 = 0;
      FUN_002188ec(&DAT_002f3f88);
      __cxa_atexit(FUN_00167a18,&DAT_002f3f88,&PTR_LOOP_002d9430);
      __cxa_guard_release(&DAT_002f3fc0);
    }
    FUN_00219108(&DAT_002f3f88,lVar6 + 0x30);
  }
  if (*(long *)(lVar2 + 0x28) == local_48) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

