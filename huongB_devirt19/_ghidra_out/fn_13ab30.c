
void FUN_0023ab30(long param_1,undefined8 param_2,undefined8 param_3)

{
  long lVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  undefined1 auStack_a8 [16];
  undefined1 auStack_98 [4];
  int local_94;
  undefined1 auStack_88 [4];
  int local_84;
  undefined1 auStack_78 [16];
  undefined1 auStack_68 [16];
  undefined1 auStack_58 [8];
  undefined8 local_50;
  long local_48;
  
  lVar1 = tpidr_el0;
  local_48 = *(long *)(lVar1 + 0x28);
  FUN_0023af68(auStack_58);
  FUN_0024fc68(auStack_78,"MSSPItem_v2");
  FUN_0020b13c(auStack_68,auStack_78,1);
  FUN_0024fe34(auStack_78);
  uVar2 = FUN_0023c3d0(local_50,auStack_68);
  uVar3 = FUN_0023c3d0(local_50,param_3);
  uVar4 = FUN_0021a64c(0x1000022,0,0,uVar2,uVar3);
  FUN_0023c054(param_1,local_50,uVar4);
  if (0 < *(int *)(param_1 + 4)) {
    FUN_0024fd5c(auStack_78,param_1);
    FUN_0020b010(auStack_88,param_3,0);
    FUN_001891f4(auStack_98,auStack_78);
    if ((0 < local_94) && (0 < local_84)) {
      FUN_0020e224(auStack_a8,auStack_98,auStack_88);
      FUN_0025009c(param_1,auStack_a8);
      FUN_0024fe34(auStack_a8);
    }
    FUN_0024fe34(auStack_98);
    FUN_0024fe34(auStack_88);
    FUN_0024fe34(auStack_78);
  }
  FUN_0023b2d8(local_50,uVar2);
  FUN_0023b2d8(local_50,uVar3);
  FUN_0023b2d8(local_50,uVar4);
  FUN_0024fe34(auStack_68);
  FUN_0023b080(auStack_58);
  if (*(long *)(lVar1 + 0x28) == local_48) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

