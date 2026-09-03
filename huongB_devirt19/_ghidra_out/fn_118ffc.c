
void FUN_00218ed0(long *param_1,long param_2,undefined8 param_3,undefined1 *param_4,long param_5)

{
  long lVar1;
  int iVar2;
  long lVar3;
  long lVar4;
  undefined8 *puVar5;
  long *plVar6;
  int iVar7;
  undefined8 *local_80;
  long *local_78;
  long local_70;
  long local_68;
  
  lVar1 = tpidr_el0;
  local_68 = *(long *)(lVar1 + 0x28);
  _ZNSt6__ndk15mutex4lockEv(param_2 + 0x10);
  lVar3 = FUN_00218980(param_2,param_3);
  if (lVar3 == 0) {
    *param_4 = 0;
    *param_1 = (long)param_1;
    param_1[1] = (long)param_1;
    param_1[2] = 0;
    for (lVar3 = *(long *)(param_5 + 8); param_5 != lVar3; lVar3 = *(long *)(lVar3 + 8)) {
      plVar6 = (long *)_Znwm(0x20);
      *plVar6 = 0;
      FUN_0024fd5c(plVar6 + 2,lVar3 + 0x10);
      lVar4 = *param_1;
      *plVar6 = lVar4;
      plVar6[1] = (long)param_1;
      *(long **)(lVar4 + 8) = plVar6;
      *param_1 = (long)plVar6;
      param_1[2] = param_1[2] + 1;
    }
  }
  else {
    *param_4 = 1;
    iVar2 = FUN_002782cc();
    if (iVar2 == 0) {
      *param_1 = (long)param_1;
      param_1[1] = (long)param_1;
      param_1[2] = 0;
      for (lVar3 = *(long *)(param_5 + 8); param_5 != lVar3; lVar3 = *(long *)(lVar3 + 8)) {
        plVar6 = (long *)_Znwm(0x20);
        *plVar6 = 0;
        FUN_0024fd5c(plVar6 + 2,lVar3 + 0x10);
        lVar4 = *param_1;
        *plVar6 = lVar4;
        plVar6[1] = (long)param_1;
        *(long **)(lVar4 + 8) = plVar6;
        *param_1 = (long)plVar6;
        param_1[2] = param_1[2] + 1;
      }
    }
    else {
      iVar2 = FUN_002765bc(lVar3);
      local_70 = 0;
      local_80 = &local_80;
      local_78 = (long *)&local_80;
      if (0 < iVar2) {
        iVar7 = 0;
        local_80 = &local_80;
        local_78 = (long *)&local_80;
        do {
          FUN_002765e4(lVar3,iVar7);
          lVar4 = FUN_00274ffc();
          if (lVar4 != 0) {
            puVar5 = (undefined8 *)_Znwm(0x20);
            *puVar5 = 0;
            FUN_0024fc68(puVar5 + 2,lVar4);
            *puVar5 = local_80;
            puVar5[1] = &local_80;
            local_80[1] = puVar5;
            local_70 = local_70 + 1;
            local_80 = puVar5;
          }
          iVar7 = iVar7 + 1;
        } while (iVar2 != iVar7);
      }
      puVar5 = local_80;
      *param_1 = (long)param_1;
      param_1[1] = (long)param_1;
      param_1[2] = 0;
      if (local_70 != 0) {
        lVar3 = *local_78;
        *(undefined8 *)(lVar3 + 8) = local_80[1];
        *(long *)local_80[1] = lVar3;
        lVar3 = *param_1;
        *(long **)(lVar3 + 8) = local_78;
        *local_78 = lVar3;
        *param_1 = (long)puVar5;
        puVar5[1] = param_1;
        param_1[2] = local_70;
        local_70 = 0;
      }
    }
  }
  _ZNSt6__ndk15mutex6unlockEv(param_2 + 0x10);
  if (*(long *)(lVar1 + 0x28) == local_68) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

