
undefined8 FUN_00167ee8(long param_1)

{
  undefined8 *puVar1;
  long lVar2;
  int iVar3;
  long lVar4;
  undefined8 *puVar5;
  undefined1 auStack_48 [16];
  long local_38;
  
  lVar2 = tpidr_el0;
  local_38 = *(long *)(lVar2 + 0x28);
  lVar4 = *(long *)(param_1 + 8);
  if (((DAT_002f4020 & 1) == 0) && (iVar3 = __cxa_guard_acquire(&DAT_002f4020), iVar3 != 0)) {
    DAT_002f4014 = 0xfff0bdc1;
    DAT_002f4000 = 0;
    DAT_002f4008 = 0;
    DAT_002f3ff8 = &PTR_FUN_002d9c90;
    DAT_002f4010 = 0;
    DAT_002f4018 = DAT_002f4014;
    __cxa_guard_release(&DAT_002f4020);
  }
  _ZNSt6__ndk15mutex4lockEv(lVar4 + 8);
  FUN_0024fd5c(auStack_48,lVar4 + 0x30);
  _ZNSt6__ndk15mutex6unlockEv(lVar4 + 8);
  FUN_002306f4(&DAT_002f3ff8,auStack_48,*(undefined4 *)(lVar4 + 0xf8),*(undefined4 *)(lVar4 + 0xfc))
  ;
  FUN_0024fe34(auStack_48);
  FUN_0016bb84(lVar4);
  FUN_0015f3b8(lVar4);
  puVar1 = *(undefined8 **)(lVar4 + 0x168);
  for (puVar5 = *(undefined8 **)(lVar4 + 0x160); puVar5 != puVar1; puVar5 = puVar5 + 1) {
    (**(code **)(*(long *)*puVar5 + 0x18))();
  }
  if (*(long *)(lVar2 + 0x28) != local_38) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}

