
void FUN_00219108(undefined8 param_1,undefined8 param_2)

{
  long lVar1;
  int iVar2;
  undefined8 *puVar3;
  undefined1 auStack_68 [16];
  undefined1 auStack_58 [16];
  undefined1 auStack_48 [4];
  int local_44;
  undefined1 auStack_38 [4];
  int local_34;
  long local_28;
  
  lVar1 = tpidr_el0;
  local_28 = *(long *)(lVar1 + 0x28);
  FUN_001891f4(auStack_38,param_2);
  if (0 < local_34) {
    if (((DAT_002fba20 & 1) == 0) && (iVar2 = __cxa_guard_acquire(&DAT_002fba20), iVar2 != 0)) {
      puVar3 = (undefined8 *)_Znam(0x10);
      puVar3[1] = 0xb2056019a5e27ce0;
      *puVar3 = 0xc1167e09a3f577f6;
      DAT_002fba18 = FUN_0027915c(puVar3,0x10);
      __cxa_guard_release(&DAT_002fba20);
    }
    FUN_0024fc68(auStack_68,DAT_002fba18);
    FUN_0020b010(auStack_58,auStack_68,1);
    FUN_0020e224(auStack_48,auStack_38,auStack_58);
    FUN_0024fe34(auStack_58);
    FUN_0024fe34(auStack_68);
    if (0 < local_44) {
      FUN_00218ce4(param_1,auStack_48);
    }
    FUN_0024fe34(auStack_48);
  }
  FUN_0024fe34(auStack_38);
  if (*(long *)(lVar1 + 0x28) == local_28) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

