
void FUN_0016e700(void)

{
  ulong uVar1;
  ulong uVar2;
  int iVar3;
  ulong uVar4;
  long lVar5;
  undefined8 *puVar6;
  undefined1 auStack_c8 [64];
  undefined1 auStack_88 [64];
  undefined8 local_48;
  
  uVar2 = DAT_002f3c78;
  uVar1 = DAT_002f3c70;
  lVar5 = tpidr_el0;
  local_48 = *(undefined8 *)(lVar5 + 0x28);
  if ((DAT_002f3c70 != 0) && (DAT_002f3c78 != 0)) {
    uVar4 = FUN_0027a17c();
    iVar3 = FUN_0027a308();
    if (((ulong)(long)iVar3 <= uVar4) &&
       ((*(ulong *)(uVar4 + 8) <= uVar1 || (uVar2 <= *(ulong *)(uVar4 + 8))))) {
      FUN_00278e34();
    }
  }
  if (((DAT_002f41f8 & 1) == 0) && (iVar3 = __cxa_guard_acquire(&DAT_002f41f8), iVar3 != 0)) {
    puVar6 = (undefined8 *)_Znam(0x11);
    *(undefined1 *)(puVar6 + 2) = 0xa7;
    puVar6[1] = 0x9e89f929a20b39f5;
    *puVar6 = 0x859df810ac2a3fe3;
    DAT_002f41f0 = FUN_0027986c(puVar6,0x11);
    __cxa_guard_release(&DAT_002f41f8);
  }
  FUN_0024fc68(auStack_88,DAT_002f41f0);
  FUN_0022cf84(auStack_c8,0);
  FUN_0024fe34(auStack_88);
  if (((DAT_002f4020 & 1) == 0) && (iVar3 = __cxa_guard_acquire(&DAT_002f4020), iVar3 != 0)) {
    DAT_002f4014 = 0xfff0bdc1;
    DAT_002f4000 = 0;
    DAT_002f4008 = 0;
    DAT_002f3ff8 = &PTR_FUN_002d9c90;
    DAT_002f4010 = 0;
    DAT_002f4018 = DAT_002f4014;
    __cxa_guard_release(&DAT_002f4020);
  }
  FUN_002313a4(&DAT_002f3ff8);
  lVar5 = FUN_0016e7ec();
                    /* WARNING: Could not recover jumptable at 0x0016e7e8. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*(code *)(lVar5 + 0x34))();
  return;
}

