
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_00161280(long param_1,long param_2,long param_3)

{
  long lVar1;
  long lVar2;
  long lVar3;
  int iVar4;
  ulong uVar5;
  undefined8 uVar6;
  long lVar7;
  long lVar8;
  long local_80 [2];
  undefined1 auStack_70 [8];
  long local_68;
  
  lVar3 = tpidr_el0;
  local_68 = *(long *)(lVar3 + 0x28);
  if ((*(int *)(param_2 + 4) == 0) || (*(int *)(param_3 + 4) == 0)) goto LAB_00161398;
  lVar1 = param_1 + 8;
  _ZNSt6__ndk15mutex4lockEv(lVar1);
  lVar8 = *(long *)(param_1 + 0x108);
  if (lVar8 == 0) {
LAB_00161320:
    local_80[0] = param_2;
    lVar8 = FUN_00169930(param_1 + 0x100,param_2,&DAT_0027c05e,local_80,auStack_70);
    FUN_0024ffbc(lVar8 + 0x30,param_3);
    uVar6 = FUN_00219314();
    uVar5 = FUN_00250660(param_2,uVar6);
  }
  else {
    lVar7 = param_1 + 0x108;
    do {
      uVar5 = FUN_002506ec(lVar8 + 0x20,param_2);
      lVar2 = 8;
      if ((uVar5 & 1) == 0) {
        lVar2 = 0;
        lVar7 = lVar8;
      }
      lVar8 = *(long *)(lVar8 + lVar2);
    } while (lVar8 != 0);
    if ((lVar7 == param_1 + 0x108) || (uVar5 = FUN_002506ec(param_2,lVar7 + 0x20), (uVar5 & 1) != 0)
       ) goto LAB_00161320;
    FUN_0024fd5c(local_80,lVar7 + 0x30);
    uVar5 = FUN_00250698(local_80,param_3);
    if ((uVar5 & 1) == 0) {
      FUN_0024fe34(local_80);
      _ZNSt6__ndk15mutex6unlockEv(lVar1);
      goto LAB_00161398;
    }
    FUN_0024ffbc(lVar7 + 0x30,param_3);
    uVar6 = FUN_00219314();
    uVar5 = FUN_00250660(param_2,uVar6);
    FUN_0024fe34(local_80);
  }
  _ZNSt6__ndk15mutex6unlockEv(lVar1);
  if ((uVar5 & 1) != 0) {
    if (((DAT_002f3fc0 & 1) == 0) && (iVar4 = __cxa_guard_acquire(&DAT_002f3fc0), iVar4 != 0)) {
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
    FUN_00219108(&DAT_002f3f88,param_3);
    FUN_0015f664(param_1,4);
  }
LAB_00161398:
  if (*(long *)(lVar3 + 0x28) != local_68) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}

