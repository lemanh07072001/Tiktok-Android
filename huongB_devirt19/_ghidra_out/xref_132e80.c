
ulong FUN_00232e80(ulong param_1,undefined8 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined1 *puVar1;
  ulong uVar2;
  code *UNRECOVERED_JUMPTABLE;
  long lVar3;
  undefined8 in_x7;
  int iVar4;
  int iVar5;
  int iVar6;
  ulong unaff_x19;
  int iVar7;
  int iVar8;
  undefined1 auStack_d0 [16];
  ulong local_c0;
  undefined8 uStack_b8;
  undefined4 local_b0;
  undefined4 uStack_ac;
  int local_6c;
  long local_68;
  
  puVar1 = auStack_d0;
  local_b0 = param_3;
  uStack_ac = param_4;
  local_c0 = param_1;
  uStack_b8 = param_2;
  lVar3 = tpidr_el0;
  local_68 = *(long *)(lVar3 + 0x28);
  iVar6 = 0xe9;
  iVar7 = 0x3e;
LAB_00232f10:
  iVar4 = iVar7;
  if (iVar6 == 0xe9) {
    if (iVar4 != 0xff) goto code_r0x00232f24;
    puVar1 = puVar1 + 0xac0;
    iVar4 = 0x3e;
    goto LAB_00232efc;
  }
  if (iVar4 == 0x3e) {
    FUN_00234998(0x14);
                    /* WARNING: Could not recover jumptable at 0x00232f70. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    uVar2 = (*UNRECOVERED_JUMPTABLE)();
    return uVar2;
  }
  if ((param_1 & 1) == 0) {
    iVar7 = 0x2f;
  }
  else {
    iVar7 = 0x68;
    iVar6 = 0x3e;
    iVar4 = 0xe9;
    while( true ) {
      while (iVar8 = iVar4, iVar4 = iVar8, iVar8 != 0xb3) {
        if (iVar6 == 0x3e) {
          *(undefined4 *)(puVar1 + 0x3c) = 0x47;
          *(undefined4 *)(puVar1 + 0x38) = 0x37;
          iVar6 = 0x3e;
          iVar4 = 0xb3;
          if ((*(int *)(puVar1 + 0x38) < 0x1f7) &&
             (iVar6 = 0xff, iVar4 = iVar8,
             (*(int *)(puVar1 + 0x3c) * *(int *)(puVar1 + 0x3c) * 4 + 4U) % 0x13 != 0)) {
            iVar6 = 0x3e;
            iVar4 = 0xb3;
          }
        }
        else {
          puVar1 = puVar1 + 0xf40;
          iVar6 = 0x3e;
          iVar4 = 0xb3;
        }
      }
      if (iVar6 == 0xff) break;
      *(undefined4 *)(puVar1 + 0x44) = 0x1c5;
      *(undefined4 *)(puVar1 + 0x40) = 0x15c;
      iVar6 = 0xff;
      if ((*(int *)(puVar1 + 0x40) < 7) &&
         ((*(int *)(puVar1 + 0x44) * *(int *)(puVar1 + 0x44) * 4 + 4U) % 0x13 == 0)) {
        iVar6 = 0xff;
        iVar4 = 0xe9;
      }
    }
  }
  if (iVar7 == 0x68) {
    iVar5 = 0x3e;
    iVar6 = 0xe9;
    iVar7 = iVar5;
  }
  else {
    iVar8 = 0xe9;
    *(long *)(puVar1 + 8) = lVar3;
    iVar6 = 0x3e;
    iVar4 = 0x3e;
    do {
      while( true ) {
        iVar5 = iVar6;
        if (iVar8 != 0xe9) {
          if (iVar4 == 0x3e) {
            uVar2 = (*(code *)(DAT_002f32f8 + -0x93aa18))
                              (*(undefined8 *)(puVar1 + 0x10),*(undefined8 *)(puVar1 + 0x18),
                               *(undefined4 *)(puVar1 + 0x20),*(undefined4 *)(puVar1 + 0x24));
            *(undefined8 *)(puVar1 + -0x10) = in_x7;
            *(undefined8 *)(puVar1 + -8) = 0x233258;
            return uVar2;
          }
          lVar3 = *(long *)(puVar1 + 8);
          iVar5 = 0x3e;
          iVar6 = 0xe9;
          unaff_x19 = 0xb071544;
          iVar7 = iVar5;
          goto LAB_00233308;
        }
        if (iVar5 == 0xff) break;
        *(undefined4 *)(puVar1 + 0x4c) = 0xc6;
        *(undefined4 *)(puVar1 + 0x48) = 0x18b;
        if (((0x5f < *(int *)(puVar1 + 0x48)) ||
            (iVar6 = 0xff, (*(int *)(puVar1 + 0x4c) * *(int *)(puVar1 + 0x4c) * 4 + 4U) % 0x13 != 0)
            ) && (iVar8 = 0xb3, iVar6 = iVar5, iVar4 = iVar5, iVar7 == 0x68)) goto LAB_002332c4;
      }
      iVar5 = 0x3e;
      iVar8 = 0xb3;
      puVar1 = puVar1 + 0x8c3;
      iVar6 = iVar5;
      iVar4 = iVar5;
    } while (iVar7 != 0x68);
LAB_002332c4:
    iVar6 = 0xb3;
    lVar3 = *(long *)(puVar1 + 8);
    iVar7 = iVar5;
  }
LAB_00233308:
  while( true ) {
    while (iVar4 = iVar7, iVar7 = iVar4, iVar6 != 0xb3) {
      if (iVar5 == 0xff) {
        puVar1 = puVar1 + 0x680;
        iVar6 = 0xb3;
        iVar5 = 0x3e;
        iVar7 = iVar5;
      }
      else {
        *(undefined4 *)(puVar1 + 0x5c) = 0x22;
        *(undefined4 *)(puVar1 + 0x58) = 0x154;
        if ((0x1d8 < *(int *)(puVar1 + 0x58)) ||
           (iVar5 = 0xff, iVar7 = 0xff,
           (*(int *)(puVar1 + 0x5c) * *(int *)(puVar1 + 0x5c) + 1U) % 7 != 0)) {
          iVar6 = 0xb3;
          iVar5 = iVar4;
          iVar7 = iVar4;
        }
      }
    }
    if (iVar5 == 0xff) break;
    local_6c = 0x9c;
    *(undefined4 *)(puVar1 + 0x60) = 0x78;
    iVar5 = 0xff;
    if ((*(int *)(puVar1 + 0x60) < 0x83) && ((local_6c * local_6c * 4 + 4U) % 0x13 == 0)) {
      iVar6 = 0xe9;
      iVar7 = iVar5;
    }
  }
  if (*(long *)(lVar3 + 0x28) == local_68) {
    return unaff_x19 & 0xffffffff;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
code_r0x00232f24:
  *(undefined4 *)(puVar1 + 0x2c) = 0x2b;
  *(undefined4 *)(puVar1 + 0x28) = 0x55;
  iVar6 = 0xe9;
  iVar7 = 0xff;
  if (*(int *)(puVar1 + 0x2c) * *(int *)(puVar1 + 0x2c) + 1 !=
      *(int *)(puVar1 + 0x28) * *(int *)(puVar1 + 0x28) * 7) {
LAB_00232efc:
    iVar6 = 0xb3;
    iVar7 = iVar4;
  }
  goto LAB_00232f10;
}

