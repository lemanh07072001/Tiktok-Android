
/* WARNING: Removing unreachable block (ram,0x00188f80) */

void FUN_001879d8(undefined8 param_1,long param_2,undefined8 param_3,ulong param_4,long param_5,
                 undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined8 param_9)

{
  code *UNRECOVERED_JUMPTABLE_00;
  int iVar1;
  undefined1 *puVar2;
  bool bVar3;
  int iVar4;
  undefined8 uVar5;
  long lVar6;
  undefined8 extraout_x1;
  undefined8 extraout_x1_00;
  undefined8 extraout_x1_01;
  long *plVar7;
  long *plVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  undefined8 *puVar12;
  long lVar13;
  int iVar14;
  uint uVar15;
  undefined8 unaff_x30;
  undefined1 auStack_2b0 [4];
  undefined4 local_2ac;
  undefined8 local_2a8;
  long local_2a0;
  int local_294;
  long local_290;
  uint local_284;
  undefined8 local_280;
  ulong local_278;
  undefined1 *local_258;
  long local_250;
  long lStack_248;
  long local_240;
  undefined1 auStack_130 [40];
  undefined8 *local_108 [2];
  undefined8 local_f8;
  undefined8 local_f0;
  undefined8 local_e8;
  undefined8 local_e0;
  undefined1 auStack_d8 [8];
  undefined8 **local_d0;
  undefined1 auStack_c8 [16];
  char local_b8;
  undefined1 auStack_b0 [32];
  undefined8 local_90;
  undefined8 uStack_88;
  undefined2 local_80;
  long local_78;
  
  puVar2 = auStack_2b0;
  local_280 = param_1;
  local_278 = param_4;
  local_290 = tpidr_el0;
  local_294 = (int)param_3;
  local_2a0 = param_2;
  local_240 = param_2 + 0x88;
  local_250 = param_5 + 8;
  lStack_248 = param_5;
  local_78 = *(long *)(local_290 + 0x28);
  local_2ac = 0xfff0bdc1;
  local_2a8 = 0xffffffffffb82f58;
  local_f8 = 1;
  local_284 = (uint)((int)param_3 == 0x138);
  iVar10 = 0xb0;
  iVar9 = 0x35;
  iVar4 = 0xc5;
  local_258 = auStack_130;
  do {
    if (iVar9 != 0x35) {
      if (iVar10 != 200) {
        *(ulong *)(puVar2 + -0x10) = param_4;
        *(undefined8 *)(puVar2 + -8) = unaff_x30;
        return;
      }
      local_f0 = 0;
      local_f8 = 1;
      UNRECOVERED_JUMPTABLE_00 = (code *)&UNK_00187c2c;
      if ((*(uint *)(puVar2 + 0x2c) & 1) == 0) {
        UNRECOVERED_JUMPTABLE_00 = (code *)0x188578;
      }
                    /* WARNING: Could not recover jumptable at 0x00187c28. Too many branches */
                    /* WARNING: Treating indirect jump as call */
      (*UNRECOVERED_JUMPTABLE_00)(0x3b);
      return;
    }
    if (iVar10 == 0xb0) {
      *(undefined4 *)(puVar2 + 0x8c) = 0x1c0;
      *(undefined4 *)(puVar2 + 0x88) = 0xd0;
      local_f0 = 8;
      UNRECOVERED_JUMPTABLE_00 = (code *)0x188564;
      if (*(int *)(puVar2 + 0x8c) * *(int *)(puVar2 + 0x8c) * -0x5e50d794 + 0xa1af286cU < 0xd79435f
          && *(int *)(puVar2 + 0x88) < 0xdc) {
        UNRECOVERED_JUMPTABLE_00 = (code *)0x187af0;
      }
                    /* WARNING: Could not recover jumptable at 0x00187bcc. Too many branches */
                    /* WARNING: Treating indirect jump as call */
      (*UNRECOVERED_JUMPTABLE_00)(0xb0);
      return;
    }
    puVar2 = puVar2 + 0x980;
    local_f0 = 0x12;
    iVar10 = 0xb0;
    iVar9 = 0x99;
    iVar14 = 0x23;
LAB_00188564:
    if (iVar14 != 0x23) {
      while (iVar9 == 0x35) {
        if (iVar10 == 0xb0) {
          *(undefined4 *)(puVar2 + 0x9c) = 0x10e;
          *(undefined4 *)(puVar2 + 0x98) = 0x1bd;
          local_f0 = 0xb;
          UNRECOVERED_JUMPTABLE_00 = (code *)0x187ddc;
          if (*(int *)(puVar2 + 0x9c) * *(int *)(puVar2 + 0x9c) * -0x49249249 + 0xb6db6db7U <
              0x24924925 && *(int *)(puVar2 + 0x98) < 0x174) {
            UNRECOVERED_JUMPTABLE_00 = (code *)0x187de4;
          }
                    /* WARNING: Could not recover jumptable at 0x00187e88. Too many branches */
                    /* WARNING: Treating indirect jump as call */
          (*UNRECOVERED_JUMPTABLE_00)(0xb0);
          return;
        }
        puVar2 = puVar2 + 0xcc1;
        local_f8 = 1;
        iVar10 = 0xb0;
        iVar9 = 0x99;
      }
      if (iVar10 != 200) {
        if (((DAT_002f4a08 & 1) == 0) && (iVar4 = __cxa_guard_acquire(&DAT_002f4a08), iVar4 != 0)) {
          FUN_0015e4a8(&DAT_002f49f0);
          __cxa_guard_release(&DAT_002f4a08);
        }
        puVar12 = *(undefined8 **)(puVar2 + 0x70);
        FUN_0015e4d4(&DAT_002f49f0,*puVar12);
        if (((DAT_002f4a08 & 1) == 0) && (iVar4 = __cxa_guard_acquire(&DAT_002f4a08), iVar4 != 0)) {
          FUN_0015e4a8(&DAT_002f49f0);
          __cxa_guard_release(&DAT_002f4a08);
        }
        FUN_0015e4cc(&DAT_002f49f0,*puVar12);
        FUN_0019368c(0x14);
        *(undefined4 *)(puVar2 + -0xb83) = 0x51;
        *(undefined4 *)(puVar2 + -0xb87) = 0xf5;
        local_e0 = 0;
        local_e8 = 0xe69;
        UNRECOVERED_JUMPTABLE_00 = (code *)0x187de4;
        if (*(int *)(puVar2 + -0xb83) * *(int *)(puVar2 + -0xb83) * -0x5e50d794 + 0xa1af286cU <
            0xd79435f && *(int *)(puVar2 + -0xb87) < 0xdc) {
          UNRECOVERED_JUMPTABLE_00 = (code *)0x187ddc;
        }
                    /* WARNING: Could not recover jumptable at 0x00187f9c. Too many branches */
                    /* WARNING: Treating indirect jump as call */
        (*UNRECOVERED_JUMPTABLE_00)(200);
        return;
      }
      local_e0 = 0;
      local_e8 = 0x82a;
      iVar14 = 0x23;
      iVar11 = 0x3b;
LAB_00188578:
      iVar10 = 0xb0;
      *(int *)(puVar2 + 0x54) = iVar4;
joined_r0x00188588:
      iVar9 = 0x35;
joined_r0x00188588:
      if (iVar4 == 0xd9) {
joined_r0x00188598:
        do {
          if (iVar11 == 0x3b) {
LAB_0018894c:
            do {
              iVar4 = iVar10;
              if (iVar14 == 0x23) {
                do {
                  while (iVar10 = iVar4, iVar9 == 0x35) {
                    if (iVar10 != 0xb0) {
                      iVar10 = 0xb0;
                      iVar9 = 0x99;
                      goto LAB_0018894c;
                    }
                    param_4 = 0;
                    unaff_x30 = 0x188978;
                    FUN_002515d0(puVar2 + 0x198,0x10);
                    *(undefined4 *)(puVar2 + 0xe4) = 0xe2;
                    *(undefined4 *)(puVar2 + 0xe0) = 0x1ad;
                    iVar1 = *(int *)(puVar2 + 0xe4);
                    iVar10 = 200;
                    param_3 = extraout_x1;
                    iVar4 = iVar10;
                    if ((199 < *(int *)(puVar2 + 0xe0)) &&
                       ((iVar1 + iVar1 * iVar1 + 7U) % 0x51 == 0)) {
                      iVar4 = *(int *)(puVar2 + 0x54);
                      iVar9 = 0x99;
                      iVar14 = 5;
                      iVar11 = 0x67;
                      goto joined_r0x00188588;
                    }
                  }
                  if (iVar10 == 200) {
                    iVar10 = 0xb0;
                    iVar9 = 0x35;
                    iVar14 = 5;
                    puVar2 = puVar2 + 0x782;
                    goto joined_r0x00188598;
                  }
                  *(undefined4 *)(puVar2 + 0xec) = 0xed;
                  *(undefined4 *)(puVar2 + 0xe8) = 0x1b8;
                  if (0x1c < *(int *)(puVar2 + 0xe8)) {
                    iVar9 = 0x35;
                    iVar14 = 5;
                    goto LAB_0018894c;
                  }
                  iVar4 = 200;
                } while ((*(int *)(puVar2 + 0xec) * *(int *)(puVar2 + 0xec) * 4 + 4U) % 0x13 == 0);
                iVar9 = 0x35;
                iVar14 = 5;
                goto LAB_0018894c;
              }
              uVar15 = *(uint *)(puVar2 + 0x28);
LAB_00188a34:
              do {
                if (iVar9 != 0x35) {
                  if (iVar10 == 0xb0) {
                    *(undefined8 *)(puVar2 + 0x48) = **(undefined8 **)(puVar2 + 0x70);
                    FUN_0024fc68(&local_90,*(undefined8 *)(puVar2 + 0x38));
                    FUN_00165a84(auStack_c8,*(undefined8 *)(puVar2 + 0x48),&local_90);
                    unaff_x30 = 0x188a74;
                    FUN_0024fe34(&local_90);
                    iVar10 = 200;
                    param_3 = extraout_x1_00;
                    iVar4 = iVar10;
                    if (local_b8 != '\0') goto LAB_00188a34;
                  }
                  else {
                    *(undefined4 *)(puVar2 + 0xfc) = 0x66;
                    *(undefined4 *)(puVar2 + 0xf8) = 0x97;
                    iVar14 = *(int *)(puVar2 + 0xfc);
                    iVar9 = 0x35;
                    iVar4 = 0xb0;
                    if (0x329161f < (iVar14 + iVar14 * iVar14) * 0x781948b1 + 0x48b0fcd7U ||
                        *(int *)(puVar2 + 0xf8) < 0x1a0) {
                      iVar4 = iVar10;
                    }
                  }
                  iVar14 = 0x23;
LAB_00188c6c:
                  uVar15 = 0;
                  goto LAB_00188c94;
                }
                if (iVar10 == 200) {
                  iVar10 = 0xb0;
                  iVar9 = 0x99;
                  *(undefined4 *)(puVar2 + 0x28) = 1;
                  if ((uVar15 & 1) == 0) {
                    iVar4 = 200;
                    goto LAB_00188c6c;
                  }
                  goto LAB_0018894c;
                }
                lVar6 = *(long *)(puVar2 + 0x10);
                param_4 = (ulong)*(uint *)(puVar2 + 0x1c);
                param_5 = *(long *)(puVar2 + 0x38);
                unaff_x30 = 0x188abc;
                (*(code *)(DAT_002f09d8 + *(long *)(puVar2 + 8)))
                          (*(undefined8 *)(puVar2 + 0x30),lVar6,puVar2 + 0x198,param_4,param_5,
                           puVar2 + 0x178);
                lVar6 = *(long *)(lVar6 + 0x88);
                *(undefined4 *)(puVar2 + 0xf4) = 0x192;
                *(undefined4 *)(puVar2 + 0xf0) = 0x47;
                iVar10 = 200;
                uVar15 = (uint)(lVar6 != 0);
                param_3 = extraout_x1_01;
              } while (*(int *)(puVar2 + 0xf4) * *(int *)(puVar2 + 0xf4) + 1 !=
                       *(int *)(puVar2 + 0xf0) * *(int *)(puVar2 + 0xf0) * 7);
              *(uint *)(puVar2 + 0x28) = uVar15;
              iVar14 = 0x23;
              iVar9 = 0x99;
            } while( true );
          }
          iVar4 = iVar10;
          if (iVar14 != 0x23) goto LAB_001888d0;
          if (iVar9 == 0x35) {
            if (iVar10 != 200) {
              lVar13 = *(long *)(puVar2 + 0x78);
              FUN_0024fd5c(&local_90,lVar13 + 0x20);
              FUN_00251d2c(&local_90);
              local_108[0] = &local_90;
              lVar6 = FUN_00169930(puVar2 + 0x178,&local_90,&DAT_0027f55c,local_108,&local_d0);
              FUN_0024ffbc(lVar6 + 0x30,lVar13 + 0x30);
              FUN_0024fe34(&local_90);
              plVar8 = *(long **)(lVar13 + 8);
              if (*(long **)(lVar13 + 8) == (long *)0x0) {
                plVar8 = (long *)(lVar13 + 0x10);
                plVar7 = (long *)*plVar8;
                if (*plVar7 != lVar13) {
                  do {
                    lVar6 = *plVar8;
                    plVar8 = (long *)(lVar6 + 0x10);
                    plVar7 = (long *)*plVar8;
                  } while (*plVar7 != lVar6);
                }
              }
              else {
                do {
                  plVar7 = plVar8;
                  plVar8 = (long *)*plVar7;
                } while ((long *)*plVar7 != (long *)0x0);
              }
              *(long **)(puVar2 + 0x78) = plVar7;
              *(undefined4 *)(puVar2 + 0xc4) = 0x116;
              *(undefined4 *)(puVar2 + 0xc0) = 0x169;
              iVar4 = *(int *)(puVar2 + 0xc4);
              local_f0 = 0;
              local_f8 = 1;
              UNRECOVERED_JUMPTABLE_00 = (code *)0x188578;
              if (0x329161f < (iVar4 + iVar4 * iVar4) * 0x781948b1 + 0x48b0fcd7U ||
                  *(int *)(puVar2 + 0xc0) < 9) {
                UNRECOVERED_JUMPTABLE_00 = (code *)0x188650;
              }
                    /* WARNING: Could not recover jumptable at 0x0018864c. Too many branches */
                    /* WARNING: Treating indirect jump as call */
              (*UNRECOVERED_JUMPTABLE_00)(0x3b);
              return;
            }
            local_f8 = 1;
            iVar14 = 5;
            iVar11 = 0x3b;
            iVar4 = 0xc5;
            goto LAB_00188578;
          }
          if (iVar10 != 200) {
            *(undefined4 *)(puVar2 + 0xcc) = 0x129;
            *(undefined4 *)(puVar2 + 200) = 0xd9;
            local_f8 = 1;
            local_e0 = 0;
            local_e8 = 0xe40;
            UNRECOVERED_JUMPTABLE_00 = (code *)&LAB_0018879c;
            if (*(int *)(puVar2 + 0xcc) * *(int *)(puVar2 + 0xcc) * -0x5e50d794 + 0xa1af286cU <
                0xd79435f && *(int *)(puVar2 + 200) < 0x78) {
              UNRECOVERED_JUMPTABLE_00 = (code *)0x188650;
            }
                    /* WARNING: Could not recover jumptable at 0x00188744. Too many branches */
                    /* WARNING: Treating indirect jump as call */
            (*UNRECOVERED_JUMPTABLE_00)();
            return;
          }
          iVar10 = 0xb0;
          iVar14 = 5;
          puVar2 = puVar2 + 0x700;
          iVar9 = 0x35;
        } while( true );
      }
      *(int *)(puVar2 + 0x48) = iVar11;
      iVar4 = *(int *)(puVar2 + 0x54);
      goto LAB_00188038;
    }
  } while( true );
LAB_001888d0:
  iVar10 = iVar4;
  if (iVar9 != 0x99) goto LAB_001887b4;
  if (iVar10 == 200) {
    puVar2 = puVar2 + 0xf00;
    iVar9 = 0x35;
    goto LAB_00188b9c;
  }
  *(undefined4 *)(puVar2 + 0xdc) = 0x13f;
  *(undefined4 *)(puVar2 + 0xd8) = 0x91;
  iVar14 = 0x23;
  if ((0xb7 < *(int *)(puVar2 + 0xd8)) ||
     (iVar4 = 200, (*(int *)(puVar2 + 0xdc) * *(int *)(puVar2 + 0xdc) + 1U) % 7 != 0)) {
    iVar4 = *(int *)(puVar2 + 0x54);
    iVar11 = 0x3b;
    goto joined_r0x00188588;
  }
  goto LAB_001888d0;
LAB_001887b4:
  if (iVar10 != 200) {
    *(undefined1 **)(puVar2 + -0x10) = &stack0xfffffffffffffff0;
    *(undefined8 *)(puVar2 + -8) = unaff_x30;
    *(undefined1 **)(puVar2 + -0x40) = puVar2 + 0x198;
    *(undefined8 *)(puVar2 + -0x38) = param_3;
    *(long *)(puVar2 + -0x30) = param_5;
    *(ulong *)(puVar2 + -0x28) = param_4;
    *(undefined8 *)(puVar2 + -0x20) = param_9;
    *(undefined8 *)(puVar2 + -0x18) = param_8;
    lVar6 = FUN_001887e0();
                    /* WARNING: Could not recover jumptable at 0x001887dc. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    (*(code *)(lVar6 + 0x34))();
    return;
  }
  iVar9 = 0x99;
LAB_00188b9c:
  iVar10 = 0xb0;
  iVar4 = *(int *)(puVar2 + 0x54);
  iVar14 = 0x23;
  iVar11 = 0x3b;
  goto joined_r0x00188588;
LAB_00188c94:
  *(uint *)(puVar2 + 0x70) = uVar15;
joined_r0x00188c9c:
  while (iVar10 = iVar9, (uVar15 & 1) != 0) {
    while( true ) {
      while (iVar9 = iVar10, iVar14 == 5) {
        do {
          while( true ) {
            while (iVar9 == 0x99) {
              bVar3 = iVar4 == 200;
              iVar4 = 200;
              if (bVar3) {
                *(undefined4 *)(puVar2 + 0x13c) = 0x196;
                *(undefined4 *)(puVar2 + 0x138) = 0x1ee;
                if ((*(int *)(puVar2 + 0x138) < 0x80) &&
                   ((*(int *)(puVar2 + 0x13c) * *(int *)(puVar2 + 0x13c) * 4 + 4U) % 0x13 == 0))
                goto LAB_0018909c;
                while( true ) {
                  FUN_0024fe34(puVar2 + 0x198);
                  FUN_00151048(puVar2 + 0x178,*(undefined8 *)(puVar2 + 0x180));
                  FUN_0022cfcc(puVar2 + 0x148);
                  *(undefined4 *)(puVar2 + 0x144) = 0x19b;
                  *(undefined4 *)(puVar2 + 0x140) = 0x189;
                  if ((0x13e < *(int *)(puVar2 + 0x140)) ||
                     ((*(int *)(puVar2 + 0x144) * *(int *)(puVar2 + 0x144) * 4 + 4U) % 0x13 != 0))
                  break;
LAB_0018909c:
                  puVar2 = puVar2 + 0xd02;
                }
                if (*(long *)(*(long *)(puVar2 + 0x20) + 0x28) != local_78) {
                    /* WARNING: Subroutine does not return */
                  __stack_chk_fail();
                }
                return;
              }
            }
            if (iVar4 != 0xb0) break;
            puVar2 = puVar2 + 0xec3;
            iVar4 = 200;
          }
          FUN_00151048(*(long *)(puVar2 + 0x30),*(undefined8 *)(*(long *)(puVar2 + 0x30) + 8));
          *(undefined4 *)(puVar2 + 0x134) = 0x1bf;
          *(undefined4 *)(puVar2 + 0x130) = 0x130;
          iVar4 = 0xb0;
          iVar10 = 0x99;
        } while ((*(int *)(puVar2 + 0x130) < 0x157) &&
                ((*(int *)(puVar2 + 0x134) * *(int *)(puVar2 + 0x134) + 1U) % 7 == 0));
      }
      if (iVar9 != 0x35) break;
      if (iVar4 != 200) goto LAB_00188d44;
      while( true ) {
        *(undefined4 *)(puVar2 + 0x124) = 0x38;
        *(undefined4 *)(puVar2 + 0x120) = 0x1d;
        iVar4 = 0xb0;
        iVar10 = 0x99;
        if ((0x1e5 < *(int *)(puVar2 + 0x120)) ||
           ((*(int *)(puVar2 + 0x124) * *(int *)(puVar2 + 0x124) * 4 + 4U) % 0x13 != 0)) break;
LAB_00188d44:
        puVar2 = puVar2 + 0xac0;
      }
    }
    uVar15 = *(uint *)(puVar2 + 0x70);
    iVar14 = 5;
    bVar3 = iVar4 == 200;
    iVar4 = 200;
    if (bVar3) {
      *(undefined4 *)(puVar2 + 300) = 0x10a;
      *(undefined4 *)(puVar2 + 0x128) = 0x19d;
      iVar9 = 0x35;
      iVar14 = 5;
      iVar4 = 0xb0;
      if (*(int *)(puVar2 + 300) * *(int *)(puVar2 + 300) + 1 !=
          *(int *)(puVar2 + 0x128) * *(int *)(puVar2 + 0x128) * 7) {
        iVar4 = 200;
      }
    }
  }
  do {
    while (iVar11 = iVar9, iVar10 = iVar4, iVar14 != 0x23) {
      do {
        while( true ) {
          while (iVar4 = iVar10, iVar11 != 0x35) {
            iVar10 = 200;
            if (iVar4 != 0xb0) {
              *(undefined4 *)(puVar2 + 0x11c) = 0x130;
              *(undefined4 *)(puVar2 + 0x118) = 0x156;
              uVar15 = 1;
              iVar14 = 0x23;
              if (*(int *)(puVar2 + 0x11c) * *(int *)(puVar2 + 0x11c) * -0x49249249 + 0xb6db6db7U <
                  0x24924925 && *(int *)(puVar2 + 0x118) < 0x70) {
                iVar4 = 0xb0;
              }
              iVar9 = 0x35;
              goto LAB_00188c94;
            }
          }
          if (iVar4 == 200) break;
          puVar2 = puVar2 + 0xf81;
          iVar10 = 200;
        }
        if (local_b8 != '\0') {
          FUN_0024fe34(auStack_c8);
        }
        *(undefined4 *)(puVar2 + 0x114) = 0x75;
        *(undefined4 *)(puVar2 + 0x110) = 0x1f1;
        iVar4 = 0xb0;
        iVar9 = 0x99;
      } while ((*(int *)(puVar2 + 0x110) < 0xc6) &&
              (iVar10 = iVar4,
              (*(int *)(puVar2 + 0x114) * *(int *)(puVar2 + 0x114) * 4 + 4U) % 0x13 == 0));
    }
    do {
      while (iVar11 != 0x35) {
        bVar3 = iVar4 == 200;
        iVar4 = 200;
        if (bVar3) {
          *(undefined4 *)(puVar2 + 0x10c) = 0x33;
          *(undefined4 *)(puVar2 + 0x108) = 0x1b1;
          iVar10 = *(int *)(puVar2 + 0x10c);
          uVar15 = *(uint *)(puVar2 + 0x70);
          iVar9 = 0x35;
          iVar4 = 0xb0;
          if (0x329161f < (iVar10 + iVar10 * iVar10) * 0x781948b1 + 0x48b0fcd7U ||
              *(int *)(puVar2 + 0x108) < 0x1c0) {
            iVar4 = 200;
          }
          iVar14 = 5;
          goto joined_r0x00188c9c;
        }
      }
      while (iVar4 != 200) {
        puVar2 = puVar2 + 0xa00;
        iVar4 = 200;
      }
      puVar12 = *(undefined8 **)(puVar2 + 0x40);
      uStack_88 = puVar12[1];
      local_90 = *puVar12;
      local_80 = *(undefined2 *)(puVar12 + 2);
      if (local_b8 == '\0') {
                    /* WARNING: Subroutine does not return */
        FUN_00193430();
      }
      uVar5 = FUN_002796e4(&local_90,0x12);
      FUN_0024fc68(local_108,uVar5);
      local_d0 = local_108;
      lVar6 = FUN_00193578(*(undefined8 *)(puVar2 + 0x30),local_108,&DAT_0027f55c,&local_d0,
                           auStack_d8);
      FUN_0024ffbc(lVar6 + 0x30,auStack_c8);
      FUN_0024fe34(local_108);
      *(undefined4 *)(puVar2 + 0x104) = 0x1ad;
      *(undefined4 *)(puVar2 + 0x100) = 0x10a;
      iVar10 = *(int *)(puVar2 + 0x104);
      iVar4 = 0xb0;
      iVar9 = 0x99;
    } while ((0xd7 < *(int *)(puVar2 + 0x100)) && ((iVar10 + iVar10 * iVar10 + 7U) % 0x51 == 0));
  } while( true );
LAB_00188038:
  if (*(int *)(puVar2 + 0x48) == 0x67) goto LAB_00188564;
  while( true ) {
    if (iVar14 != 0x23) {
      if (iVar9 == 0x35) {
        if (iVar10 != 0xb0) {
          *(undefined1 **)(puVar2 + 400) = puVar2 + 0x178;
          (*(code *)(DAT_002f09d0 + -0x47d0a8))
                    (puVar2 + 0x198,puVar2 + 400,*(undefined8 *)(DAT_002f0a20 + -0x47d0a8));
          local_e0 = 0;
          local_e8 = 0x439;
          local_f8 = 1;
          UNRECOVERED_JUMPTABLE_00 = (code *)0x188578;
          if (*(int *)(puVar2 + 0x19c) < 1) {
            UNRECOVERED_JUMPTABLE_00 = (code *)&LAB_00188550;
          }
                    /* WARNING: Could not recover jumptable at 0x0018854c. Too many branches */
                    /* WARNING: Treating indirect jump as call */
          (*UNRECOVERED_JUMPTABLE_00)(0x67);
          return;
        }
        local_f8 = 1;
        local_f0 = 10;
        UNRECOVERED_JUMPTABLE_00 = (code *)0x188310;
        if (*(long *)(puVar2 + 0x78) != *(long *)(puVar2 + 0x80)) {
          UNRECOVERED_JUMPTABLE_00 = (code *)0x188044;
        }
                    /* WARNING: Could not recover jumptable at 0x00188380. Too many branches */
                    /* WARNING: Treating indirect jump as call */
        (*UNRECOVERED_JUMPTABLE_00)(0xb0);
        return;
      }
      if (iVar10 != 200) {
        *(undefined4 *)(puVar2 + 0xbc) = 0x50;
        *(undefined4 *)(puVar2 + 0xb8) = 0x81;
        local_f0 = 0xb;
        local_f8 = 1;
        UNRECOVERED_JUMPTABLE_00 = (code *)0x188310;
        if (*(int *)(puVar2 + 0xbc) * *(int *)(puVar2 + 0xbc) + 1 !=
            *(int *)(puVar2 + 0xb8) * *(int *)(puVar2 + 0xb8) * 7) {
          UNRECOVERED_JUMPTABLE_00 = (code *)0x188578;
        }
                    /* WARNING: Could not recover jumptable at 0x00188410. Too many branches */
                    /* WARNING: Treating indirect jump as call */
        (*UNRECOVERED_JUMPTABLE_00)(0x67);
        return;
      }
      puVar2 = puVar2 + 0xb43;
      local_f0 = 7;
      iVar14 = 0x23;
      iVar11 = 0x67;
      iVar4 = 0xd9;
      goto LAB_00188578;
    }
    if (iVar9 == 0x99) break;
    if (iVar10 != 200) {
      *(undefined4 *)(puVar2 + 0xac) = 0x140;
      *(undefined4 *)(puVar2 + 0xa8) = 0xf0;
      local_f8 = 1;
      local_e0 = 0;
      local_e8 = 0xc64;
      UNRECOVERED_JUMPTABLE_00 = (code *)0x188044;
      if (*(int *)(puVar2 + 0xac) * *(int *)(puVar2 + 0xac) * -0x5e50d794 + 0xa1af286cU < 0xd79435f
          && *(int *)(puVar2 + 0xa8) < 0x161) {
        UNRECOVERED_JUMPTABLE_00 = (code *)0x188054;
      }
                    /* WARNING: Could not recover jumptable at 0x001882bc. Too many branches */
                    /* WARNING: Treating indirect jump as call */
      (*UNRECOVERED_JUMPTABLE_00)(iVar10);
      return;
    }
    puVar2 = puVar2 + 0xb43;
    local_e0 = 0;
    local_e8 = 0x4f0;
    iVar10 = 0xb0;
    iVar9 = 0x99;
  }
  if (iVar10 == 0xb0) {
    uVar5 = FUN_0027915c(auStack_b0,0x14);
    FUN_0024fc68(&local_90,uVar5);
    FUN_0022cf84(puVar2 + 0x148,1,&local_90,10);
    *(undefined8 *)(puVar2 + -0x10) = param_7;
    *(undefined8 *)(puVar2 + -8) = 0x188090;
    return;
  }
  local_e0 = 0;
  local_e8 = 0xe46;
  iVar10 = 0xb0;
  iVar9 = 0x35;
  iVar14 = 5;
  goto LAB_00188038;
}

