
/* WARNING: Removing unreachable block (ram,0x00172284) */
/* WARNING: Removing unreachable block (ram,0x0017228c) */
/* WARNING: Removing unreachable block (ram,0x00172294) */
/* WARNING: Removing unreachable block (ram,0x00172260) */
/* WARNING: Removing unreachable block (ram,0x00172278) */
/* WARNING: Removing unreachable block (ram,0x00172298) */
/* WARNING: Removing unreachable block (ram,0x001722fc) */
/* WARNING: Removing unreachable block (ram,0x00172320) */
/* WARNING: Removing unreachable block (ram,0x00172324) */
/* WARNING: Removing unreachable block (ram,0x0017227c) */
/* WARNING: Removing unreachable block (ram,0x0017232c) */
/* WARNING: Removing unreachable block (ram,0x00172380) */
/* WARNING: Removing unreachable block (ram,0x00172384) */
/* WARNING: Removing unreachable block (ram,0x00173810) */
/* WARNING: Removing unreachable block (ram,0x00173298) */
/* WARNING: Removing unreachable block (ram,0x00170cb4) */
/* WARNING: Removing unreachable block (ram,0x00173e04) */
/* WARNING: Removing unreachable block (ram,0x00170abc) */
/* WARNING: Removing unreachable block (ram,0x00170524) */
/* WARNING: Removing unreachable block (ram,0x00170180) */
/* WARNING: Removing unreachable block (ram,0x00170a58) */
/* WARNING: Removing unreachable block (ram,0x0017103c) */
/* WARNING: Removing unreachable block (ram,0x00172ed0) */
/* WARNING: Removing unreachable block (ram,0x001718a8) */
/* WARNING: Removing unreachable block (ram,0x001705e4) */
/* WARNING: Removing unreachable block (ram,0x00170770) */
/* WARNING: Removing unreachable block (ram,0x00170810) */
/* WARNING: Type propagation algorithm not settling */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

code * FUN_0016fb60(code *param_1,undefined8 param_2,undefined1 *param_3,code *param_4,
                   undefined8 **param_5,undefined1 *param_6,ulong param_7)

{
  uint *puVar1;
  char *pcVar2;
  char cVar3;
  int iVar4;
  undefined1 *puVar5;
  code *pcVar6;
  undefined1 *puVar7;
  bool bVar8;
  byte bVar9;
  uint uVar10;
  uint uVar11;
  int iVar12;
  undefined4 uVar13;
  undefined4 uVar14;
  int iVar15;
  ulong uVar16;
  undefined1 *puVar17;
  uint uVar18;
  int iVar19;
  undefined8 uVar20;
  uint uVar21;
  long lVar22;
  undefined8 **ppuVar23;
  uint uVar24;
  uint uVar25;
  undefined8 uVar26;
  char *pcVar27;
  undefined8 *puVar28;
  ulong uVar29;
  ulong extraout_x12;
  ulong extraout_x12_00;
  ulong extraout_x12_01;
  ulong extraout_x12_02;
  ulong extraout_x12_03;
  ulong extraout_x12_04;
  ulong extraout_x12_05;
  ulong extraout_x12_06;
  ulong extraout_x12_07;
  ulong extraout_x12_08;
  long lVar30;
  code *pcVar31;
  code *extraout_x14;
  code *extraout_x14_00;
  code *extraout_x14_01;
  code *extraout_x14_02;
  code *extraout_x14_03;
  code *extraout_x14_04;
  code *extraout_x14_05;
  code *extraout_x14_06;
  code *extraout_x14_07;
  code *extraout_x14_08;
  long *plVar32;
  code *pcVar33;
  code *extraout_x15;
  code *pcVar34;
  long lVar35;
  undefined8 *puVar36;
  code *pcVar37;
  int iVar38;
  undefined8 *puVar39;
  undefined8 uVar40;
  undefined4 unaff_w24;
  undefined8 *puVar41;
  undefined8 *puVar42;
  ulong unaff_x26;
  undefined8 uVar43;
  undefined8 *puVar44;
  double dVar45;
  undefined1 auVar46 [16];
  undefined1 auStack_5d0 [76];
  undefined4 local_584;
  code *local_560;
  undefined8 local_558;
  undefined8 local_548;
  long local_538;
  undefined4 local_51c;
  undefined8 local_508;
  undefined8 **local_500;
  undefined8 *local_4f0;
  undefined1 *local_4d8;
  code *local_4b8;
  code *pcStack_4b0;
  undefined8 local_4a8;
  code *local_4a0;
  undefined1 auStack_e8 [16];
  undefined8 *puStack_d8;
  undefined8 auStack_d0 [2];
  undefined1 auStack_c0 [4];
  int iStack_bc;
  undefined1 auStack_b0 [4];
  int iStack_ac;
  long lStack_a8;
  undefined1 auStack_a0 [4];
  int iStack_9c;
  undefined1 auStack_90 [16];
  long local_80;
  
  puVar7 = auStack_5d0;
  local_500 = param_5;
  local_560 = param_4;
  local_4d8 = param_3;
  local_4a8 = param_2;
  local_538 = tpidr_el0;
  local_4a0 = param_1 + 0x58;
  local_4b8 = param_1 + 0x60;
  pcStack_4b0 = param_1;
  local_51c = 0x1f;
  pcVar31 = FUN_0016fb60;
  local_558 = 0xffffffffff52bec0;
  ppuVar23 = &puStack_d8;
  local_80 = *(long *)(local_538 + 0x28);
  local_548 = 0xffffffffff52bec0;
  uVar11 = 0;
  puVar39 = (undefined8 *)0x7b;
  local_584 = 0xfff0bdc1;
  local_4f0 = auStack_d0;
  local_508 = 0xffffffffff52bec0;
  uVar20 = 0x48;
  uVar43 = 1;
  puVar36 = (undefined8 *)&SUB_24924925;
LAB_0016fc78:
  pcVar33 = (code *)0x1e;
  uVar21 = uVar11;
  do {
    uVar11 = uVar21;
    if ((int)puVar39 != 0x7b) {
      if (uVar11 == 0) {
        *(int *)(puVar7 + 0xa4) = (int)param_3;
        FUN_00174744(0x10);
        uVar43 = (*(code *)(DAT_002f02d0 + *(long *)(puVar7 + -0x1271)))(&puStack_d8);
        FUN_0024fc68(puVar7 + -0xe31,uVar43);
        FUN_0022d530(puVar7 + -0xe71,0,puVar7 + -0xe31);
        auVar46 = FUN_0024fe34(puVar7 + -0xe31);
        *(undefined1 **)(puVar7 + -0x12f9) = &stack0xfffffffffffffff0;
        *(undefined8 *)(puVar7 + -0x12f1) = 0x16fd38;
        *(undefined1 (*) [16])(puVar7 + -0x1339) = auVar46;
        *(ulong *)(puVar7 + -0x1329) = (ulong)*(uint *)(puVar7 + -0x1245);
        *(code **)(puVar7 + -0x1321) = param_4;
        *(undefined8 ***)(puVar7 + -0x1319) = param_5;
        *(undefined1 **)(puVar7 + -0x1311) = param_6;
        *(ulong *)(puVar7 + -0x1309) = param_7;
        *(undefined8 *)(puVar7 + -0x1301) = uVar20;
        lVar30 = FUN_0016fd88(0x16fd40);
                    /* WARNING: Could not recover jumptable at 0x0016fd84. Too many branches */
                    /* WARNING: Treating indirect jump as call */
        pcVar31 = (code *)(*(code *)(lVar30 + 0x38))();
        return pcVar31;
      }
      puVar39 = (undefined8 *)0x7b;
      puVar42 = (undefined8 *)0x95;
      if ((*(uint *)(puVar7 + 0x34) & 1) == 0) {
        *(undefined8 ***)(puVar7 + 0x40) = ppuVar23;
        param_7 = 0x89;
        iVar12 = 0x77;
        uVar29 = 0xb9;
        iVar38 = 0x73;
        *(undefined4 *)(puVar7 + 0x34) = 0;
        goto LAB_0017039c;
      }
      uVar11 = 0;
      *(undefined4 *)(puVar7 + 0x34) = 1;
      goto LAB_0016fefc;
    }
    if (uVar11 == 0x39) {
      uVar11 = 0;
      puVar7 = puVar7 + 0x983;
      break;
    }
    *(undefined4 *)(puVar7 + 0x14c) = 0x48;
    *(undefined4 *)(puVar7 + 0x148) = 0x1d0;
    puVar39 = (undefined8 *)0x7b;
    uVar21 = 0x39;
  } while (*(int *)(puVar7 + 0x14c) * *(int *)(puVar7 + 0x14c) + 1 ==
           *(int *)(puVar7 + 0x148) * *(int *)(puVar7 + 0x148) * 7);
  puVar39 = (undefined8 *)0x8d;
  puVar42 = (undefined8 *)0x3;
LAB_0016fefc:
  pcVar33 = (code *)0x1e;
  *(undefined8 ***)(puVar7 + 0x40) = ppuVar23;
  uVar21 = uVar11;
  if ((int)puVar42 == 3) goto LAB_0016fc78;
  do {
    if ((int)puVar39 != 0x8d) {
      if (uVar11 != 0x39) {
        *(undefined4 *)(puVar7 + 0x30) = 0;
        *(undefined1 **)(puVar7 + -0x10) = param_3;
        *(undefined8 *)(puVar7 + -8) = 0x1d0;
        return param_1;
      }
      *(undefined4 *)(puVar7 + 0x15c) = 0x4a;
      *(undefined4 *)(puVar7 + 0x158) = 0x10a;
      pcVar31 = (code *)0xd79435e;
      uVar11 = 0x39;
      if (*(int *)(puVar7 + 0x15c) * *(int *)(puVar7 + 0x15c) * -0x5e50d794 + 0xa1af286cU <
          0xd79435f && *(int *)(puVar7 + 0x158) < 0x17a) {
        uVar11 = 0;
      }
      puVar39 = (undefined8 *)0x8d;
      *(ulong *)(puVar7 + 0x88) = (ulong)*(uint *)(puVar7 + 0x30);
      uVar21 = uVar11;
    }
    if (uVar21 == 0) {
      puVar7 = puVar7 + 0xec2;
    }
    *(undefined4 *)(puVar7 + 0x164) = 0x1e;
    *(undefined4 *)(puVar7 + 0x160) = 0x19b;
    if (0x96 < *(int *)(puVar7 + 0x160)) break;
    uVar10 = *(int *)(puVar7 + 0x164) * *(int *)(puVar7 + 0x164) * 4 + 4;
    pcVar31 = (code *)(ulong)(uVar10 - (int)((ulong)uVar10 * 0xaf286bcb >> 0x20));
    uVar21 = 0;
  } while (uVar10 % 0x13 == 0);
  uVar11 = 0;
  *(long *)(puVar7 + 0x50) = (long)(int)*(undefined8 *)(puVar7 + 0x88);
  puVar39 = (undefined8 *)0x7b;
  puVar42 = (undefined8 *)0x3;
  *(uint *)(puVar7 + 0x3c) =
       (uint)((ulong)(long)(int)*(undefined8 *)(puVar7 + 0x88) < *(ulong *)(puVar7 + 0x60));
  iVar12 = *(int *)(puVar7 + 0xb4);
  param_7 = 0x28;
joined_r0x00170070:
  if (iVar12 != 0x77) {
    *(int *)(puVar7 + 0xb4) = iVar12;
    if ((int)param_7 != 0x89) {
      param_1 = (code *)0xd0;
      pcVar27 = (char *)(*(long *)(puVar7 + 0x80) + *(long *)(puVar7 + 0x50));
      uVar21 = *(uint *)(puVar7 + 0x3c);
LAB_00171374:
      iVar12 = (int)puVar42;
      uVar10 = uVar11;
joined_r0x00171378:
      uVar11 = uVar10;
      if (iVar12 == 3) {
        iVar12 = (int)puVar39;
        puVar44 = puVar39;
        do {
          if (iVar12 == 0x7b) {
            if (uVar10 == 0x39) {
              *(undefined4 *)(puVar7 + 0x16c) = 0x15d;
              *(undefined4 *)(puVar7 + 0x168) = 0x18e;
              pcVar31 = (code *)0x24924924;
              uVar10 = 0x39;
              if (*(int *)(puVar7 + 0x16c) * *(int *)(puVar7 + 0x16c) * -0x49249249 + 0xb6db6db7U <
                  0x24924925 && *(int *)(puVar7 + 0x168) < 0xb1) {
                uVar10 = 0;
              }
              puVar44 = (undefined8 *)0x8d;
              goto LAB_00171400;
            }
            uVar10 = 0x39;
            if ((uVar21 & 1) != 0) goto LAB_00171454;
          }
          else {
LAB_00171400:
            if (uVar10 == 0x39) {
              *(undefined4 *)(puVar7 + 0x174) = 0x181;
              *(undefined4 *)(puVar7 + 0x170) = 0xe9;
              uVar10 = 0;
              puVar42 = (undefined8 *)0x95;
              uVar18 = *(int *)(puVar7 + 0x174) * *(int *)(puVar7 + 0x174) + 1;
              pcVar33 = (code *)(ulong)(uVar18 - (int)((ulong)uVar18 * 0x24924925 >> 0x20));
              pcVar31 = (code *)(ulong)((uVar18 / 7) * -7);
              puVar39 = (undefined8 *)0x7b;
              uVar11 = uVar10;
              if ((0xe0 < *(int *)(puVar7 + 0x170)) || (uVar11 = 0, uVar18 % 7 != 0))
              goto LAB_00171374;
            }
            else {
              puVar7 = puVar7 + 0x442;
              uVar10 = 0x39;
            }
          }
          iVar12 = (int)puVar44;
        } while( true );
      }
      goto LAB_00171468;
    }
    ppuVar23 = *(undefined8 ***)(puVar7 + 0x40);
    goto LAB_0016fefc;
  }
  if ((int)param_7 != 0x89) goto LAB_00170194;
LAB_0017007c:
  puVar44 = puVar39;
  while ((int)puVar42 != 0x95) {
LAB_001700dc:
    puVar1 = (uint *)(puVar7 + 0x94);
    while( true ) {
      uVar21 = uVar11;
      while ((int)puVar44 != 0x7b) {
        if (uVar21 != 0) {
          cVar3 = *(char *)(*(long *)(puVar7 + 0x68) + 1);
          *(undefined4 *)(puVar7 + 0x194) = 0xf5;
          *(undefined4 *)(puVar7 + 400) = 0x1ff;
          iVar12 = *(int *)(puVar7 + 0x194);
          *(uint *)(puVar7 + 0x38) = (uint)(cVar3 == -10);
          if ((0xbb < *(int *)(puVar7 + 400)) &&
             (uVar11 = 0, (iVar12 + iVar12 * iVar12 + 7U) % 0x51 == 0)) goto LAB_001700dc;
          uVar11 = 0;
          puVar42 = (undefined8 *)0x95;
          puVar39 = (undefined8 *)0x7b;
          goto LAB_0017007c;
        }
        puVar7 = puVar7 + 0xd02;
        uVar21 = 0x39;
      }
      if (uVar21 != 0) break;
      uVar11 = 0x39;
      if ((*puVar1 & 1) == 0) {
        *(undefined4 *)(puVar7 + 0x94) = 0;
        uVar11 = 0;
        puVar39 = (undefined8 *)0x8d;
        puVar42 = (undefined8 *)0x95;
        goto LAB_00170194;
      }
    }
    *(undefined4 *)(puVar7 + 0x18c) = 0x187;
    *(undefined4 *)(puVar7 + 0x188) = 0x102;
    iVar12 = *(int *)(puVar7 + 0x18c);
    uVar11 = 0;
    if (0x329161f < (iVar12 + iVar12 * iVar12) * 0x781948b1 + 0x48b0fcd7U ||
        *(int *)(puVar7 + 0x188) < 0xc0) {
      uVar11 = uVar21;
    }
    puVar44 = (undefined8 *)0x8d;
  }
  uVar21 = *(uint *)(puVar7 + 0x5c);
  pcVar33 = (code *)0x181;
LAB_00170dbc:
  do {
    while ((int)puVar44 != 0x8d) {
      if (uVar11 != 0) {
        *(undefined4 *)(puVar7 + 0x19c) = 0x10a;
        *(undefined4 *)(puVar7 + 0x198) = 0x35;
        if (*(int *)(puVar7 + 0x19c) * *(int *)(puVar7 + 0x19c) * -0x5e50d794 + 0xa1af286cU <
            0xd79435f && *(int *)(puVar7 + 0x198) < 0xeb) {
          uVar11 = 0;
        }
        puVar44 = (undefined8 *)0x8d;
        goto LAB_00170dbc;
      }
      uVar11 = 0x39;
      if ((*(uint *)(puVar7 + 0x38) & 1) == 0) {
        uVar11 = 0;
        puVar39 = (undefined8 *)0x8d;
        puVar42 = (undefined8 *)0x95;
        goto LAB_00170198;
      }
    }
    while (uVar11 == 0) {
      puVar7 = puVar7 + 0xac1;
      uVar11 = 0x39;
    }
    uVar11 = 0;
    puVar39 = (undefined8 *)0x7b;
    puVar42 = (undefined8 *)0x3;
    cVar3 = *(char *)(*(long *)(puVar7 + 0x68) + 2);
    *(undefined4 *)(puVar7 + 0x1a4) = 0x1d0;
    *(undefined4 *)(puVar7 + 0x1a0) = 0x181;
    uVar21 = (uint)(cVar3 == 'w');
    if ((0xe3 < *(int *)(puVar7 + 0x1a0)) ||
       ((*(int *)(puVar7 + 0x1a4) * *(int *)(puVar7 + 0x1a4) * 4 + 4U) % 0x13 != 0))
    goto LAB_00170198;
  } while( true );
LAB_00170194:
  uVar21 = *(uint *)(puVar7 + 0x5c);
LAB_00170198:
  *(uint *)(puVar7 + 0x5c) = uVar21;
LAB_001701a4:
  pcVar31 = (code *)(ulong)uVar11;
  iVar15 = (int)puVar42;
  do {
    while (iVar19 = (int)puVar39, iVar15 != 0x95) {
      while( true ) {
        while (uVar11 = (uint)pcVar31, iVar19 == 0x8d) {
          if (uVar11 == 0x39) {
            cVar3 = *(char *)(*(long *)(puVar7 + 0x68) + 3);
            *(undefined4 *)(puVar7 + 0x1b4) = 0x7e;
            *(undefined4 *)(puVar7 + 0x1b0) = 0x102;
            *(uint *)(puVar7 + 0xc4) = (uint)(cVar3 == -1);
            iVar12 = *(int *)(puVar7 + 0x1b0) * *(int *)(puVar7 + 0x1b0);
            pcVar33 = (code *)(ulong)(uint)(iVar12 * 8);
            pcVar31 = (code *)0x0;
            if (*(int *)(puVar7 + 0x1b4) * *(int *)(puVar7 + 0x1b4) + 1 != iVar12 * 7) {
              puVar42 = (undefined8 *)0x95;
              puVar39 = (undefined8 *)0x7b;
              uVar11 = 0;
              goto LAB_001701a4;
            }
          }
          else {
            puVar7 = puVar7 + 0x782;
            pcVar31 = (code *)0x39;
          }
        }
        if (uVar11 == 0x39) break;
        pcVar31 = (code *)0x39;
        if ((uVar21 & 1) == 0) {
          puVar42 = (undefined8 *)0x95;
          puVar39 = (undefined8 *)0x8d;
          goto LAB_001701a4;
        }
      }
      *(undefined4 *)(puVar7 + 0x1ac) = 0x10f;
      *(undefined4 *)(puVar7 + 0x1a8) = 0x195;
      iVar12 = *(int *)(puVar7 + 0x1ac);
      pcVar33 = (code *)0x48b0fcd7;
      uVar11 = 0;
      if (0x329161f < (iVar12 + iVar12 * iVar12) * 0x781948b1 + 0x48b0fcd7U ||
          *(int *)(puVar7 + 0x1a8) < 0x21) {
        uVar11 = 0x39;
      }
      pcVar31 = (code *)(ulong)uVar11;
      puVar39 = (undefined8 *)0x8d;
    }
    do {
      while (uVar11 = (uint)pcVar31, iVar19 != 0x7b) {
        if (uVar11 == 0x39) {
          puVar7 = puVar7 + 0x7c0;
          puVar39 = (undefined8 *)0x7b;
LAB_00170398:
          uVar11 = 0;
          puVar42 = (undefined8 *)0x3;
          uVar29 = 0x14;
          iVar12 = 0x1f;
          param_7 = 0x89;
          iVar38 = 0x46;
          goto LAB_0017039c;
        }
        *(undefined4 *)(puVar7 + 0x1bc) = 0x9a;
        *(undefined4 *)(puVar7 + 0x1b8) = 0xd;
        uVar21 = *(uint *)(puVar7 + 0x1bc);
        pcVar31 = (code *)(ulong)uVar21;
        pcVar33 = (code *)(ulong)*(uint *)(puVar7 + 0x1b8);
        puVar39 = (undefined8 *)0x7b;
        puVar42 = (undefined8 *)0x3;
        param_7 = 0x89;
        iVar12 = 0x1f;
        uVar29 = 0x14;
        iVar38 = 0x46;
        if (0xdd < (int)*(uint *)(puVar7 + 0x1b8)) goto LAB_0017039c;
        uVar21 = (uVar21 * uVar21 + 1) % 7;
        pcVar33 = (code *)(ulong)uVar21;
        pcVar31 = (code *)0x39;
        if (uVar21 != 0) goto LAB_0017039c;
      }
      if (uVar11 != 0) {
        puVar39 = (undefined8 *)0x8d;
        *(long *)(puVar7 + 0x10) = *(long *)(puVar7 + 0x80) + *(long *)(puVar7 + 0x50) + 4;
        goto LAB_00170398;
      }
      pcVar31 = (code *)0x39;
    } while ((*(uint *)(puVar7 + 0xc4) & 1) != 0);
    uVar21 = *(uint *)(puVar7 + 0x5c);
    *(undefined4 *)(puVar7 + 0xc4) = 0;
    pcVar31 = (code *)0x0;
    puVar39 = (undefined8 *)0x8d;
  } while( true );
LAB_00171454:
  puVar42 = (undefined8 *)0x95;
  puVar39 = (undefined8 *)0x7b;
  uVar11 = uVar10;
LAB_00171468:
  if ((int)puVar39 == 0x8d) {
    if (uVar10 == 0) {
      puVar7 = puVar7 + 0xf43;
    }
    cVar3 = *pcVar27;
    *(undefined4 *)(puVar7 + 0x184) = 0xd0;
    *(undefined4 *)(puVar7 + 0x180) = 0x13e;
    pcVar31 = (code *)(ulong)*(uint *)(puVar7 + 0x180);
    if ((int)*(uint *)(puVar7 + 0x180) < 0x133) goto code_r0x00171498;
    goto LAB_0017151c;
  }
  if (uVar10 == 0) {
    uVar26 = *(undefined8 *)(puVar7 + 200);
    iVar12 = *(int *)(puVar7 + 0xb4);
    uVar11 = 0;
    puVar39 = (undefined8 *)0x8d;
    puVar42 = (undefined8 *)0x3;
    param_7 = 0x89;
    uVar29 = 0x14;
    iVar38 = 0x46;
    *(undefined8 *)(puVar7 + 0x10) = *(undefined8 *)(puVar7 + 0x80);
    goto LAB_001703a0;
  }
  *(undefined4 *)(puVar7 + 0x17c) = 0x1c;
  *(undefined4 *)(puVar7 + 0x178) = 0x10b;
  pcVar31 = (code *)0xd79435e;
  if (*(int *)(puVar7 + 0x17c) * *(int *)(puVar7 + 0x17c) * -0x5e50d794 + 0xa1af286cU < 0xd79435f &&
      *(int *)(puVar7 + 0x178) < 0x5b) {
    uVar11 = 0;
  }
  iVar12 = (int)puVar42;
  puVar39 = (undefined8 *)0x8d;
  uVar10 = uVar11;
  goto joined_r0x00171378;
code_r0x00171498:
  uVar18 = *(int *)(puVar7 + 0x184) * *(int *)(puVar7 + 0x184) * 4 + 4;
  pcVar33 = (code *)(ulong)(uVar18 - (int)((ulong)uVar18 * 0xaf286bcb >> 0x20));
  pcVar31 = (code *)(ulong)(uVar18 % 0x13);
  uVar10 = 0;
  if (uVar18 % 0x13 != 0) {
LAB_0017151c:
    uVar11 = 0;
    puVar39 = (undefined8 *)0x7b;
    puVar42 = (undefined8 *)0x3;
    param_7 = 0x89;
    iVar12 = 0x77;
    *(uint *)(puVar7 + 0x94) = (uint)(cVar3 == -0xf);
    goto LAB_00171548;
  }
  goto LAB_00171468;
LAB_001703a0:
  *(undefined8 *)(puVar7 + 200) = uVar26;
LAB_001703a8:
  *(int *)(puVar7 + 0xa4) = iVar38;
  if (iVar38 != 0x46) {
    if ((int)uVar29 != 0xb9) goto LAB_00171bc8;
LAB_001703bc:
    if (iVar12 == 0x1f) {
      uVar21 = *(uint *)(puVar7 + 0xf4);
      uVar10 = uVar21 << 8 ^ uVar21 >> 8;
      ppuVar23 = (undefined8 **)(ulong)uVar21;
      pcVar31 = (code *)(ulong)*(uint *)(puVar7 + 0xe8);
      uVar21 = uVar11;
LAB_00170444:
      pcVar33 = (code *)(ulong)uVar10;
      *(int *)(puVar7 + 0xf4) = (int)ppuVar23;
      *(int *)(puVar7 + 0xe8) = (int)pcVar31;
      param_1 = (code *)(ulong)((int)pcVar31 + 1);
      param_5 = (undefined8 **)((ulong)param_5 & 0xffffffff);
      param_4 = (code *)((ulong)param_4 & 0xffffffff);
      do {
        if ((int)param_7 != 0x28) {
          param_3 = (undefined1 *)((ulong)param_3 & 0xffffffff);
          do {
            uVar18 = uVar21;
            if ((int)puVar42 == 0x95) {
              lVar30 = *(long *)(puVar7 + 0x138);
              lVar35 = *(long *)(puVar7 + 0x140);
              pcVar31 = param_4;
              ppuVar23 = param_5;
              uVar11 = uVar21;
              goto LAB_00170564;
            }
            do {
              uVar11 = uVar21;
              if ((int)puVar39 != 0x7b) goto LAB_00170668;
              if (uVar18 != 0x39) {
                puVar7 = puVar7 + 0xbc3;
              }
              *(undefined4 *)(puVar7 + 0x244) = 0x35;
              *(undefined4 *)(puVar7 + 0x240) = 0x19c;
              uVar18 = 0;
              uVar11 = *(int *)(puVar7 + 0x244) * *(int *)(puVar7 + 0x244) * 4 + 4;
              param_6 = (undefined1 *)(ulong)(uVar11 - (int)((ulong)uVar11 * 0xaf286bcb >> 0x20));
            } while ((*(int *)(puVar7 + 0x240) < 0xab) && (uVar11 % 0x13 == 0));
            uVar11 = 0;
            puVar39 = (undefined8 *)0x8d;
            *(int *)(puVar7 + 0x10c) = (int)uVar26 + 1;
LAB_00170668:
            if (uVar18 != 0x39) {
              puVar42 = (undefined8 *)0x95;
              uVar29 = 0x14;
              iVar38 = 0x46;
              *(undefined4 *)(puVar7 + 0xb0) = *(undefined4 *)(puVar7 + 0x10c);
              pcVar31 = param_4;
              goto LAB_001703a8;
            }
            *(undefined4 *)(puVar7 + 0x24c) = 0x183;
            *(undefined4 *)(puVar7 + 0x248) = 0x4b;
            iVar38 = *(int *)(puVar7 + 0x24c);
            puVar39 = (undefined8 *)0x7b;
            uVar21 = 0;
            if (0x329161f < (iVar38 + iVar38 * iVar38) * 0x781948b1 + 0x48b0fcd7U ||
                *(int *)(puVar7 + 0x248) < 0x10a) {
              uVar21 = uVar11;
            }
            puVar42 = (undefined8 *)0x95;
            *(undefined8 *)(puVar7 + 0x140) = *(undefined8 *)(puVar7 + 0x110);
          } while ((int)param_7 != 0x28);
          *(undefined8 *)(puVar7 + 0x140) = *(undefined8 *)(puVar7 + 0x110);
        }
        puVar17 = (undefined1 *)(ulong)(pcVar31 < (code *)(unaff_x26 >> 2));
        if ((int)puVar42 == 3) {
          do {
            puVar5 = (undefined1 *)((ulong)param_3 & 0xffffffff);
LAB_00170490:
            do {
              param_3 = puVar5;
              if ((int)puVar39 != 0x7b) {
                if (uVar21 == 0x39) {
                  *(undefined4 *)(puVar7 + 0x26c) = 0x13e;
                  *(undefined4 *)(puVar7 + 0x268) = 0x25;
                  puVar39 = (undefined8 *)0x7b;
                  uVar21 = 0x39;
                  if (*(int *)(puVar7 + 0x26c) * *(int *)(puVar7 + 0x26c) * -0x5e50d794 +
                      0xa1af286cU < 0xd79435f && *(int *)(puVar7 + 0x268) < 0x9a) {
                    uVar21 = 0;
                  }
                }
                else {
                  uVar21 = 0x39;
                  puVar5 = (undefined1 *)0x0;
                  if (((ulong)param_3 & 1) == 0) goto LAB_00170490;
                }
                puVar42 = (undefined8 *)0x95;
                goto LAB_00170730;
              }
              if (uVar21 == 0) {
                puVar7 = puVar7 + 0xec2;
              }
              *(undefined4 *)(puVar7 + 0x264) = 0x4c;
              *(undefined4 *)(puVar7 + 0x260) = 0x161;
              if (0xd6 < *(int *)(puVar7 + 0x260)) break;
              uVar21 = 0;
              *(code **)(puVar7 + 0x100) = pcVar31;
              puVar5 = puVar17;
            } while ((*(int *)(puVar7 + 0x264) * *(int *)(puVar7 + 0x264) + 1U) % 7 == 0);
            uVar21 = 0;
            puVar39 = (undefined8 *)0x8d;
            *(code **)(puVar7 + 0x100) = pcVar31;
            param_3 = puVar17;
          } while( true );
        }
LAB_00170730:
        param_3 = (undefined1 *)((ulong)param_3 & 0xffffffff);
        iVar38 = (int)puVar39;
        uVar11 = uVar21;
        while (iVar38 == 0x7b) {
          if (uVar21 != 0x39) {
            puVar7 = puVar7 + 0xb82;
          }
          *(undefined4 *)(puVar7 + 0x274) = 0x1f1;
          *(undefined4 *)(puVar7 + 0x270) = 0xad;
          uVar21 = 0;
          uVar18 = *(int *)(puVar7 + 0x274) * *(int *)(puVar7 + 0x274) * 4 + 4;
          param_6 = (undefined1 *)(ulong)(uVar18 - (int)((ulong)uVar18 * 0xaf286bcb >> 0x20));
          if ((0x14d < *(int *)(puVar7 + 0x270)) || (uVar18 % 0x13 != 0)) {
            uVar11 = 0;
            puVar39 = (undefined8 *)0x8d;
            *(uint *)(puVar7 + 0xdc) = (uint)((int)ppuVar23 != 0x77df8b85);
          }
          iVar38 = (int)puVar39;
        }
        if (uVar21 != 0x39) {
          param_7 = 0x89;
          puVar39 = (undefined8 *)0x7b;
          uVar21 = 3;
          if ((*(uint *)(puVar7 + 0xdc) & 1) == 0) {
            uVar21 = (uint)puVar42;
          }
          puVar42 = (undefined8 *)(ulong)uVar21;
          iVar12 = 0x77;
          goto LAB_001703bc;
        }
        param_7 = 0x89;
        uVar21 = 0x39;
        param_5 = (undefined8 **)
                  (ulong)(uVar10 ^ *(uint *)(*(long *)(puVar7 + 0x138) +
                                            *(long *)(puVar7 + 0x100) * 4));
        param_4 = param_1;
      } while( true );
    }
    *(undefined8 *)(puVar7 + 0x110) = 0xffffffffff52bec0;
    uVar43 = 0xaf286bcb;
    goto LAB_00171634;
  }
  pcVar27 = *(char **)(puVar7 + 0x68);
  if ((int)uVar29 != 0xb9) {
    param_6 = (undefined1 *)((ulong)param_3 & 0xffffffff);
    if (iVar12 == 0x77) {
      uVar10 = *(uint *)(puVar7 + 0x18);
    }
    else {
      param_1 = *(code **)(puVar7 + 0x138);
      iVar15 = (int)*(undefined8 *)(puVar7 + 0x88) + 1;
      while ((int)param_7 == 0x89) {
LAB_0017087c:
        if ((int)puVar42 == 3) goto LAB_00170978;
        uVar21 = *(uint *)(puVar7 + 0xb0);
        uVar10 = uVar11;
LAB_001708dc:
        if ((int)puVar39 == 0x7b) {
          if (uVar11 == 0x39) {
            uVar11 = 0;
            uVar21 = 0;
            puVar39 = (undefined8 *)0x8d;
            uVar10 = uVar11;
            goto LAB_001708dc;
          }
          *(undefined4 *)(puVar7 + 0x1d4) = 0x5f;
          *(undefined4 *)(puVar7 + 0x1d0) = 0x131;
          uVar18 = *(uint *)(puVar7 + 0x1d4);
          pcVar31 = (code *)(ulong)uVar18;
          uVar11 = 0x39;
          if (0x4a < *(int *)(puVar7 + 0x1d0)) goto LAB_001708dc;
          uVar18 = uVar18 * uVar18 * 4 + 4;
          pcVar33 = (code *)(ulong)(uVar18 / 0x13);
          uVar18 = uVar18 % 0x13;
          pcVar31 = (code *)(ulong)uVar18;
          if (uVar18 == 0) goto LAB_0017088c;
          goto LAB_001708dc;
        }
        if (uVar10 == 0) {
          *(undefined4 *)(puVar7 + 0x1dc) = 0x71;
          *(undefined4 *)(puVar7 + 0x1d8) = 0x154;
          uVar11 = 0x39;
          iVar38 = *(int *)(puVar7 + 0x1d8) * *(int *)(puVar7 + 0x1d8);
          pcVar33 = (code *)(ulong)(uint)(iVar38 * 8);
          uVar18 = iVar38 * 7;
          pcVar31 = (code *)(ulong)uVar18;
          *(ulong *)(puVar7 + 200) = (ulong)uVar21;
          uVar10 = uVar11;
          if (*(int *)(puVar7 + 0x1dc) * *(int *)(puVar7 + 0x1dc) + 1U != uVar18) {
            puVar39 = (undefined8 *)0x7b;
            puVar42 = (undefined8 *)0x3;
            param_7 = 0x28;
            *(uint *)(puVar7 + 0xb0) = uVar21;
            *(ulong *)(puVar7 + 200) = (ulong)uVar21;
            uVar11 = 0;
            goto joined_r0x00170a80;
          }
          goto LAB_001708dc;
        }
        *(uint *)(puVar7 + 0xb0) = uVar21;
        puVar39 = (undefined8 *)0x7b;
        puVar42 = (undefined8 *)0x3;
        param_7 = 0x28;
        puVar7 = puVar7 + 0x8c3;
        uVar11 = 0;
joined_r0x00170a80:
        if (iVar12 == 0x77) {
          uVar10 = *(uint *)((long)puVar7 + 0x18);
          *(code **)((long)puVar7 + 0x138) = param_1;
          goto LAB_00170e68;
        }
      }
      *(code **)(puVar7 + 0x138) = param_1;
      pcVar31 = (code *)(long)(int)*(undefined8 *)(puVar7 + 200);
      pcVar33 = (code *)(ulong)(pcVar31 < *(code **)(puVar7 + 0x60));
      if ((int)puVar42 == 0x95) {
        pcVar34 = (code *)(ulong)*(uint *)(puVar7 + 0x24);
      }
      else {
        param_1 = (code *)(ulong)*(uint *)(puVar7 + 0x24);
        do {
          uVar26 = *(undefined8 *)(puVar7 + 0xb8);
          pcVar34 = param_1;
          uVar21 = uVar11;
          while( true ) {
            if ((int)puVar39 == 0x8d) {
              if (uVar11 == 0) {
                uVar11 = 0x39;
                puVar39 = (undefined8 *)0x8d;
                param_7 = 0x89;
                iVar38 = 0x73;
                *(undefined8 *)(puVar7 + 0x110) = *(undefined8 *)(puVar7 + 0x40);
                *(char **)(puVar7 + 0x68) = pcVar27;
                *(undefined8 *)(puVar7 + 0xb8) = uVar26;
                *(int *)(puVar7 + 0x24) = (int)param_1;
                goto LAB_00170d60;
              }
              *(undefined4 *)(puVar7 + 0x1ec) = 0x160;
              *(undefined4 *)(puVar7 + 0x1e8) = 0x4f;
              if (*(int *)(puVar7 + 0x1ec) * *(int *)(puVar7 + 0x1ec) * -0x5e50d794 + 0xa1af286cU <
                  0xd79435f && *(int *)(puVar7 + 0x1e8) < 0x1ed) {
                uVar11 = 0;
              }
              puVar39 = (undefined8 *)0x7b;
              *(undefined8 *)(puVar7 + 0xb8) = uVar26;
              pcVar34 = param_1;
              goto LAB_00170c00;
            }
            if (uVar21 == 0x39) break;
            *(undefined4 *)(puVar7 + 0x1e4) = 0x15b;
            *(undefined4 *)(puVar7 + 0x1e0) = 0x7c;
            uVar21 = 0x39;
            *(code **)(puVar7 + 0xb8) = pcVar31;
            pcVar34 = pcVar33;
            if ((*(int *)(puVar7 + 0x1e0) < 0x121) &&
               (*(code **)(puVar7 + 0xb8) = pcVar31, param_3 = param_6,
               (*(int *)(puVar7 + 0x1e4) * *(int *)(puVar7 + 0x1e4) + 1U) % 7 == 0)) {
              param_1 = *(code **)(puVar7 + 0x138);
              puVar39 = (undefined8 *)0x8d;
              puVar42 = (undefined8 *)0x95;
              param_7 = 0x89;
              *(code **)(puVar7 + 0xb8) = pcVar31;
              *(uint *)(puVar7 + 0x24) = (uint)(pcVar31 < *(code **)(puVar7 + 0x60));
              uVar11 = uVar21;
              goto joined_r0x00170a80;
            }
          }
          uVar11 = 0x39;
          if (((ulong)pcVar34 & 1) == 0) {
            uVar11 = 0;
          }
          puVar39 = (undefined8 *)0x8d;
          param_1 = pcVar34;
        } while ((int)puVar42 != 0x95);
      }
LAB_00170c00:
      *(int *)(puVar7 + 0x24) = (int)pcVar34;
      pcVar2 = (char *)(*(long *)(puVar7 + 0x138) + *(long *)(puVar7 + 0xb8));
      uVar21 = *(uint *)(puVar7 + 0x18);
LAB_00170c20:
      do {
        uVar10 = uVar21;
        if ((int)puVar39 != 0x8d) {
          if (uVar11 == 0) {
            puVar7 = puVar7 + 0xbc0;
          }
          cVar3 = *pcVar2;
          *(undefined4 *)(puVar7 + 500) = 0x70;
          *(undefined4 *)(puVar7 + 0x1f0) = 0x7d;
          pcVar33 = (code *)(ulong)*(uint *)(puVar7 + 0x1f0);
          uVar21 = (uint)(cVar3 == -0xf);
          uVar11 = 0;
          if ((int)*(uint *)(puVar7 + 0x1f0) < 0x174) {
            uVar10 = *(int *)(puVar7 + 500) * *(int *)(puVar7 + 500) * 4 + 4;
            pcVar33 = (code *)(ulong)(uVar10 - (int)((ulong)uVar10 * 0xaf286bcb >> 0x20));
            *(char **)(puVar7 + 0xa8) = pcVar2;
            if (uVar10 % 0x13 == 0) goto LAB_00170c20;
          }
          puVar39 = (undefined8 *)0x8d;
          *(char **)(puVar7 + 0xa8) = pcVar2;
          uVar11 = 0;
          uVar10 = uVar21;
        }
        param_1 = pcVar34;
        if (uVar11 != 0) {
          *(undefined4 *)(puVar7 + 0x1fc) = 0x101;
          *(undefined4 *)(puVar7 + 0x1f8) = 0xd;
          puVar39 = (undefined8 *)0x7b;
          puVar42 = (undefined8 *)0x3;
          if (*(int *)(puVar7 + 0x1fc) * *(int *)(puVar7 + 0x1fc) * -0x5e50d794 + 0xa1af286cU <
              0xd79435f && *(int *)(puVar7 + 0x1f8) < 0x180) {
            uVar11 = 0;
          }
          param_7 = 0x89;
          goto LAB_00170e68;
        }
        uVar11 = 0x39;
        uVar21 = 1;
      } while ((uVar10 & 1) != 0);
      puVar39 = (undefined8 *)0x8d;
      puVar42 = (undefined8 *)0x95;
    }
LAB_00170e68:
    iVar12 = (int)puVar42;
    uVar21 = *(uint *)(puVar7 + 0x1c);
    *(int *)(puVar7 + 0xb4) = (int)param_5;
joined_r0x00170e74:
    if ((int)param_7 != 0x28) {
      while (iVar12 = (int)puVar39, (int)puVar42 != 0x95) {
        do {
          while (iVar12 != 0x7b) {
            if (uVar11 != 0) {
              *(undefined4 *)(puVar7 + 0x20c) = 0x1e7;
              *(undefined4 *)(puVar7 + 0x208) = 0x1a1;
              pcVar33 = (code *)(ulong)*(uint *)(puVar7 + 0x208);
              puVar39 = (undefined8 *)0x7b;
              if (*(int *)(puVar7 + 0x20c) * *(int *)(puVar7 + 0x20c) * -0x5e50d794 + 0xa1af286cU <
                  0xd79435f && (int)*(uint *)(puVar7 + 0x208) < 0x189) {
                uVar11 = 0;
              }
              puVar42 = (undefined8 *)0x95;
              iVar12 = 0x95;
              goto joined_r0x00170e74;
            }
            uVar11 = 0x39;
            uVar18 = uVar21 & 1;
            uVar21 = 1;
            if (uVar18 == 0) {
              uVar21 = 0;
              iVar12 = 0x95;
              goto LAB_00170f78;
            }
          }
          if (uVar11 == 0) {
            puVar7 = puVar7 + 0xc80;
          }
          cVar3 = *(char *)(*(long *)(puVar7 + 0xa8) + 1);
          *(undefined4 *)(puVar7 + 0x204) = 0x14;
          *(undefined4 *)(puVar7 + 0x200) = 0x5c;
          iVar38 = *(int *)(puVar7 + 0x204);
          pcVar33 = (code *)(ulong)*(uint *)(puVar7 + 0x200);
        } while ((0x1fc < (int)*(uint *)(puVar7 + 0x200)) &&
                (uVar11 = 0, uVar21 = (uint)(cVar3 == -10),
                (iVar38 + iVar38 * iVar38 + 7U) % 0x51 == 0));
        uVar11 = 0;
        puVar39 = (undefined8 *)0x8d;
        uVar21 = (uint)(cVar3 == -10);
      }
      lVar30 = *(long *)(puVar7 + 0x28);
      uVar18 = *(uint *)(puVar7 + 0x20);
      lVar35 = *(long *)(puVar7 + 0xb8);
      uVar24 = *(uint *)(puVar7 + 8);
      goto joined_r0x0017120c;
    }
LAB_00170f78:
    lVar30 = *(long *)(puVar7 + 0x28);
    uVar18 = *(uint *)(puVar7 + 0x20);
    lVar35 = *(long *)(puVar7 + 0xb8);
    goto LAB_00170f8c;
  }
LAB_00171548:
  *(char **)(puVar7 + 0x68) = pcVar27;
  goto joined_r0x00170070;
LAB_00170564:
  uVar21 = uVar11;
  param_5 = ppuVar23;
  param_4 = pcVar31;
  uVar11 = uVar21;
  do {
    if ((int)puVar39 == 0x8d) {
      pcVar31 = (code *)0x0;
      ppuVar23 = (undefined8 **)0x20190512;
      uVar11 = 0x39;
      if (uVar21 == 0) goto LAB_00170564;
      *(undefined4 *)(puVar7 + 0x25c) = 0xee;
      *(undefined4 *)(puVar7 + 600) = 0;
      param_7 = 0x28;
      puVar42 = (undefined8 *)0x3;
      uVar10 = (uint)param_5 << 8 ^ (uint)param_5 >> 8;
      if (*(int *)(puVar7 + 0x25c) * *(int *)(puVar7 + 0x25c) * -0x5e50d794 + 0xa1af286cU <
          0xd79435f && *(int *)(puVar7 + 600) < 0x1d4) {
        uVar21 = 0;
      }
      puVar39 = (undefined8 *)0x7b;
      ppuVar23 = param_5;
      pcVar31 = param_4;
      goto LAB_00170444;
    }
    if (uVar11 != 0x39) {
      puVar7 = puVar7 + 0xb41;
    }
    *(undefined4 *)(puVar7 + 0x254) = 0x4b;
    *(undefined4 *)(puVar7 + 0x250) = 0x1c4;
    if (0x2f < *(int *)(puVar7 + 0x250)) break;
    uVar10 = *(int *)(puVar7 + 0x254) * *(int *)(puVar7 + 0x254) + 1;
    param_6 = (undefined1 *)(ulong)(uVar10 - (int)((ulong)uVar10 * 0x24924925 >> 0x20));
    uVar11 = 0;
  } while (uVar10 % 7 == 0);
  puVar39 = (undefined8 *)0x8d;
  pcVar31 = param_4;
  ppuVar23 = param_5;
  uVar11 = 0;
  unaff_x26 = lVar35 - lVar30;
  goto LAB_00170564;
LAB_00171634:
  uVar26 = *(undefined8 *)(puVar7 + 0xf8);
LAB_00171650:
  do {
    pcVar31 = (code *)(ulong)uVar11;
    if ((int)param_7 != 0x89) {
      iVar12 = *(int *)(puVar7 + 0x140);
      iVar38 = *(int *)(puVar7 + 0x138);
      pcVar34 = (code *)(ulong)*(uint *)(puVar7 + 0x100);
LAB_00171984:
      do {
        uVar11 = (uint)pcVar31;
        pcVar31 = pcVar34;
        puVar36 = puVar39;
        uVar21 = uVar11;
LAB_00171998:
        do {
          iVar15 = (int)puVar39;
          pcVar33 = pcVar31;
          if ((int)puVar42 != 3) {
LAB_00171ab4:
            pcVar31 = (code *)0x153;
            pcVar33 = pcVar34;
            do {
              uVar10 = *(uint *)(puVar7 + 0x10c);
              *(undefined4 *)(puVar7 + 0x100) = unaff_w24;
              uVar11 = uVar21;
              while ((int)puVar36 == 0x7b) {
                if (uVar11 != 0) {
                  iVar12 = *(int *)(puVar7 + 0x140);
                  iVar38 = *(int *)(puVar7 + 0x138);
                  if ((uVar10 & 1) == 0) {
                    uVar11 = 0;
                  }
                  unaff_w24 = 0;
                  puVar36 = (undefined8 *)0x8d;
                  *(uint *)(puVar7 + 0x10c) = uVar10;
                  iVar15 = 0x8d;
                  pcVar33 = pcVar34;
                  uVar21 = uVar11;
                  if ((int)puVar42 == 3) goto LAB_001719a4;
                  goto LAB_00171ab4;
                }
                uVar10 = FUN_00235658(&DAT_002f4230);
                *(undefined4 *)(puVar7 + 0x2a4) = 0x1de;
                *(undefined4 *)(puVar7 + 0x2a0) = 0x145;
                iVar12 = *(int *)(puVar7 + 0x2a4);
                uVar11 = 0x39;
                pcVar31 = extraout_x14;
                pcVar33 = extraout_x15;
                if ((0x8c < *(int *)(puVar7 + 0x2a0)) &&
                   (puVar39 = (undefined8 *)0x8d, (iVar12 + iVar12 * iVar12 + 7U) % 0x51 == 0)) {
                  unaff_w24 = *(undefined4 *)(puVar7 + 0x100);
                  iVar12 = *(int *)(puVar7 + 0x140);
                  iVar38 = *(int *)(puVar7 + 0x138);
                  puVar42 = (undefined8 *)0x3;
                  *(uint *)(puVar7 + 0x10c) = uVar10;
                  pcVar31 = pcVar34;
                  puVar36 = puVar39;
                  uVar21 = uVar11;
                  goto LAB_00171998;
                }
              }
              unaff_w24 = 1;
              bVar8 = uVar21 == 0x39;
              uVar21 = 0x39;
              if (bVar8) {
                *(undefined4 *)(puVar7 + 0x2ac) = 0x84;
                *(undefined4 *)(puVar7 + 0x2a8) = 0xb3;
                uVar29 = 0x6f;
                puVar39 = (undefined8 *)0x7b;
                puVar42 = (undefined8 *)0x3;
                param_7 = 0x89;
                uVar11 = 0x39;
                if (*(int *)(puVar7 + 0x2ac) * *(int *)(puVar7 + 0x2ac) * -0x5e50d794 + 0xa1af286cU
                    < 0xd79435f && *(int *)(puVar7 + 0x2a8) < 0x70) {
                  uVar11 = 0;
                }
                iVar12 = 0x1f;
                goto LAB_00171bc8;
              }
            } while( true );
          }
LAB_001719a4:
          pcVar31 = (code *)(ulong)uVar11;
          if (iVar15 != 0x7b) {
            if (uVar11 != 0x39) goto code_r0x001719b8;
            pcVar31 = (code *)0x0;
            puVar7 = puVar7 + 0x8c3;
            goto LAB_0017197c;
          }
          if (uVar11 != 0x39) {
            *(undefined4 *)(puVar7 + 0x294) = 0xab;
            *(undefined4 *)(puVar7 + 0x290) = 0x153;
            iVar19 = 0;
            if (iVar38 != 0) {
              iVar19 = iVar12 / iVar38;
            }
            bVar8 = iVar12 == iVar19 * iVar38;
            pcVar33 = (code *)(ulong)bVar8;
            uVar11 = 0x39;
            if ((*(int *)(puVar7 + 0x290) < 0x193) &&
               ((*(int *)(puVar7 + 0x294) * *(int *)(puVar7 + 0x294) * 4 + 4U) % 0x13 == 0)) {
              param_7 = 0x89;
              puVar42 = (undefined8 *)0x95;
              puVar39 = (undefined8 *)0x8d;
              *(uint *)(puVar7 + 0x100) = (uint)bVar8;
              goto LAB_00171634;
            }
            goto LAB_001719a4;
          }
          pcVar31 = (code *)0x0;
          puVar39 = (undefined8 *)0x8d;
          uVar11 = 0;
        } while (((ulong)pcVar33 & 1) == 0);
        pcVar34 = (code *)0x1;
        puVar42 = (undefined8 *)0x95;
      } while( true );
    }
    do {
      while ((int)puVar42 != 0x95) {
        while( true ) {
          while (puVar36 = puVar39, puVar39 = puVar36, (int)puVar36 != 0x8d) {
            pcVar33 = (code *)0x0;
            if ((int)pcVar31 == 0) {
              *(undefined4 *)(puVar7 + 0x27c) = 0xce;
              *(undefined4 *)(puVar7 + 0x278) = 0x8d;
              pcVar31 = pcVar33;
              puVar39 = (undefined8 *)0x8d;
              if ((*(int *)(puVar7 + 0x278) < 0x16b) &&
                 (pcVar31 = (code *)0x39, puVar39 = puVar36,
                 (*(int *)(puVar7 + 0x27c) * *(int *)(puVar7 + 0x27c) + 1U) % 7 != 0)) {
                pcVar31 = pcVar33;
                puVar39 = (undefined8 *)0x8d;
              }
            }
            else {
              puVar7 = puVar7 + 0xa40;
              pcVar31 = pcVar33;
              puVar39 = (undefined8 *)0x8d;
            }
          }
          if ((int)pcVar31 == 0x39) break;
          FUN_00278e34();
          *(undefined4 *)(puVar7 + 0x284) = 0x29;
          *(undefined4 *)(puVar7 + 0x280) = 0x15;
          pcVar31 = (code *)0x39;
          if ((*(int *)(puVar7 + 0x280) < 0x86) &&
             ((*(int *)(puVar7 + 0x284) * *(int *)(puVar7 + 0x284) * 4 + 4U) % 0x13 == 0)) {
            pcVar31 = (code *)0x39;
            puVar39 = (undefined8 *)0x7b;
          }
        }
        pcVar31 = (code *)0x0;
        puVar39 = (undefined8 *)0x7b;
        puVar42 = (undefined8 *)0x95;
      }
LAB_00171678:
      do {
        uVar11 = (uint)pcVar31;
        if ((int)puVar39 == 0x8d) {
          if (uVar11 == 0x39) {
            uVar11 = 0;
            puVar7 = puVar7 + 0xf00;
          }
          else {
            *(undefined4 *)(puVar7 + 0x28c) = 0x60;
            *(undefined4 *)(puVar7 + 0x288) = 399;
            pcVar31 = (code *)0x39;
            if (*(int *)(puVar7 + 0x28c) * *(int *)(puVar7 + 0x28c) + 1 ==
                *(int *)(puVar7 + 0x288) * *(int *)(puVar7 + 0x288) * 7) goto LAB_00171678;
          }
          param_7 = 0x28;
          puVar42 = (undefined8 *)0x3;
          puVar39 = (undefined8 *)0x7b;
          goto LAB_00171650;
        }
        pcVar31 = (code *)0x39;
      } while (uVar11 == 0);
      param_4 = (code *)FUN_00165a74(**(undefined8 **)(puVar7 + 0x130));
      FUN_00242660(puVar7 + 0x498,uVar26,0,*(undefined8 *)(puVar7 + 0x128));
      FUN_0024fa94(puVar7 + 0x4a8);
      if (((DAT_002f42e8 & 1) == 0) && (iVar12 = __cxa_guard_acquire(&DAT_002f42e8), iVar12 != 0)) {
        FUN_002349ac(&DAT_002f4230);
        __cxa_atexit(FUN_0016ec7c,&DAT_002f4230,&PTR_LOOP_002d9430);
        __cxa_guard_release(&DAT_002f42e8);
      }
      uVar40 = *(undefined8 *)(puVar7 + 0x118);
      _ZNSt6__ndk15mutex4lockEv(uVar40);
      iVar12 = *(int *)(*(long *)(puVar7 + 0x120) + 0x88);
      *(int *)(puVar7 + 0x140) = iVar12;
      *(int *)(*(long *)(puVar7 + 0x120) + 0x88) = iVar12 + 1;
      _ZNSt6__ndk15mutex6unlockEv(uVar40);
      if (((DAT_002f3fc0 & 1) == 0) && (iVar12 = __cxa_guard_acquire(&DAT_002f3fc0), iVar12 != 0)) {
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
      uVar40 = (*(code *)(DAT_002f02d8 + *(long *)(puVar7 + 0x110)))(&puStack_d8);
      FUN_0024fc68(puVar7 + 0x4b8,uVar40);
      param_3 = puVar7 + 0x4b8;
      dVar45 = (double)FUN_00219600(0x4000000000000000,&DAT_002f3f88,0);
      FUN_0024fe34(puVar7 + 0x4b8);
      pcVar31 = (code *)0x0;
      *(int *)(puVar7 + 0x138) = (int)dVar45;
      puVar39 = (undefined8 *)0x8d;
      unaff_w24 = 0;
    } while (0 < (int)dVar45);
    param_7 = 0x28;
  } while( true );
LAB_00171bc8:
  if (iVar12 == 0x77) {
    iVar12 = 0x77;
  }
  else {
    *(int *)(puVar7 + 0xb4) = iVar12;
    uVar26 = *(undefined8 *)(puVar7 + 0x70);
    uVar21 = uVar11;
    do {
      pcVar31 = pcVar33;
      if ((int)param_7 == 0x28) {
        pcVar31 = (code *)FUN_00171fa8();
        return pcVar31;
      }
      while( true ) {
        pcVar33 = (code *)((ulong)pcVar31 & 0xffffffff);
        if ((uint)puVar42 != 3) break;
        while( true ) {
          if ((int)puVar39 != 0x8d) {
            if (uVar21 == 0) {
              puVar7 = puVar7 + 0xd02;
            }
            uVar11 = FUN_0016577c(**(undefined8 **)(puVar7 + 0x130));
            FUN_0016ba50(puVar7 + 0x4b8,uVar11 & 1);
            *(undefined1 **)(puVar7 + -0x10) = &stack0xfffffffffffffff0;
            *(undefined8 *)(puVar7 + -8) = 0x171cfc;
            *(undefined1 **)(puVar7 + -0x40) = auStack_e8;
            *(undefined8 *)(puVar7 + -0x38) = uVar26;
            *(code **)(puVar7 + -0x30) = param_4;
            *(undefined1 **)(puVar7 + -0x28) = param_3;
            *(undefined8 *)(puVar7 + -0x20) = uVar20;
            *(ulong *)(puVar7 + -0x18) = param_7;
            lVar30 = FUN_00171d24();
                    /* WARNING: Could not recover jumptable at 0x00171d20. Too many branches */
                    /* WARNING: Treating indirect jump as call */
            pcVar31 = (code *)(*(code *)(lVar30 + 0x34))();
            return pcVar31;
          }
          if (uVar21 == 0x39) break;
          uVar21 = 0x39;
          uVar29 = (ulong)pcVar33 & 1;
          pcVar33 = (code *)0x1;
          if (uVar29 == 0) {
            pcVar31 = (code *)FUN_00171e04();
            return pcVar31;
          }
        }
        *(undefined4 *)(puVar7 + 700) = 0x1ea;
        *(undefined4 *)(puVar7 + 0x2b8) = 0x1ea;
        uVar21 = 0x39;
        if (*(int *)(puVar7 + 700) * *(int *)(puVar7 + 700) * -0x5e50d794 + 0xa1af286cU < 0xd79435f
            && *(int *)(puVar7 + 0x2b8) < 0xce) {
          uVar21 = 0;
        }
        puVar39 = (undefined8 *)0x7b;
        puVar42 = (undefined8 *)0x95;
        pcVar31 = pcVar33;
        if ((int)param_7 == 0x28) {
          pcVar31 = FUN_0016fb60;
          uVar29 = 0xa061440a061440;
          *(undefined8 *)(puVar7 + 0x138) = 0xffffffffff52bec0;
          *(int *)(puVar7 + 0x140) = (int)pcVar33;
          *(undefined8 *)(puVar7 + 0x120) = uVar43;
          *(undefined8 *)(puVar7 + 0x128) = 0xffffffffff52bec0;
          *(undefined8 **)(puVar7 + 0x118) = puVar36;
          uVar11 = uVar21;
          goto LAB_00172060;
        }
      }
      pcVar33 = (code *)((ulong)pcVar31 & 0xffffffff);
      do {
        while ((int)puVar39 == 0x7b) {
          if (uVar21 == 0x39) {
            uVar43 = (*(code *)(lRam00000000002f02e0 + -0xad4140))(auStack_90);
            FUN_002503bc(&puStack_d8,uVar26,uVar43);
            FUN_0024ffbc(auStack_e8,&puStack_d8);
            FUN_0024fe34(&puStack_d8);
            *(undefined4 *)(puVar7 + 0x2c4) = 0x14;
            *(undefined4 *)(puVar7 + 0x2c0) = 0xe2;
            uVar21 = 0;
            if (*(int *)(puVar7 + 0x2c4) * *(int *)(puVar7 + 0x2c4) + 1 !=
                *(int *)(puVar7 + 0x2c0) * *(int *)(puVar7 + 0x2c0) * 7) {
              puVar39 = (undefined8 *)0x8d;
            }
          }
          else {
            puVar7 = puVar7 + 0x501;
            uVar21 = 0x39;
          }
        }
        bVar8 = uVar21 == 0;
        uVar21 = 0x39;
      } while (bVar8);
      puVar36 = (undefined8 *)(*(code *)(lRam00000000002f02e8 + -0xad4140))(&puStack_d8);
      uVar43 = FUN_002185d0();
      FUN_0024fc68(&puStack_d8,puVar36);
      bVar9 = FUN_002181a8(uVar43,&puStack_d8);
      FUN_0024fe34(&puStack_d8);
      iVar12 = FUN_001611fc(**(undefined8 **)(puVar7 + 0x130));
      uVar11 = 3;
      if ((iVar12 != 5 & (bVar9 ^ 1)) == 0) {
        uVar11 = (uint)puVar42;
      }
      puVar42 = (undefined8 *)(ulong)uVar11;
      uVar11 = 0;
      uVar21 = 0;
      puVar39 = (undefined8 *)0x7b;
      param_7 = 0x28;
    } while (*(int *)(puVar7 + 0xb4) != 0x77);
    iVar12 = 0x77;
    uVar29 = extraout_x12;
    pcVar31 = extraout_x14_00;
  }
  goto LAB_001723b0;
LAB_00172060:
  uVar10 = uVar21;
  if ((int)puVar39 == 0x7b) {
    if (uVar10 == 0x39) {
      uVar10 = 0;
      puVar36 = (undefined8 *)0x8d;
      puVar7 = puVar7 + 0xac2;
      goto LAB_00172050;
    }
    *(undefined4 *)(puVar7 + 0x2dc) = 0x97;
    *(undefined4 *)(puVar7 + 0x2d8) = 0x48;
    puVar36 = (undefined8 *)0x8d;
    if (0x1e3 < *(int *)(puVar7 + 0x2d8)) goto LAB_00172050;
    uVar18 = (*(int *)(puVar7 + 0x2dc) * *(int *)(puVar7 + 0x2dc) * 4 + 4U) % 0x13;
    uVar29 = (ulong)uVar18;
    uVar21 = 0x39;
    if (uVar18 != 0) {
LAB_00172050:
      uVar21 = uVar10;
      puVar39 = puVar36;
      uVar11 = uVar10;
    }
    goto LAB_00172060;
  }
  if (uVar10 != 0x39) {
    if (((DAT_002f4128 & 1) == 0) && (iVar12 = __cxa_guard_acquire(&DAT_002f4128), iVar12 != 0)) {
      FUN_002356b8(&DAT_002f4058);
      __cxa_atexit(FUN_00168328,&DAT_002f4058,&PTR_LOOP_002d9430);
      __cxa_guard_release(&DAT_002f4128);
    }
    puVar36 = *(undefined8 **)(puVar7 + 0x130);
    FUN_0015f5cc(&puStack_d8,*puVar36);
    FUN_00238558(&DAT_002f4058,&puStack_d8,0x73);
    FUN_0024fe34(&puStack_d8);
    puStack_d8 = *(undefined8 **)(puVar7 + 0xe0);
    param_5 = &puStack_d8;
    *puStack_d8 = 0;
    puStack_d8[1] = 0;
    uVar11 = FUN_002080d8(puVar7 + 0x4b8,auStack_e8,puVar7 + 0x498,puVar7 + 0x4a8,param_5,3);
    FUN_00151048(&puStack_d8,auStack_d0[0]);
    if (((DAT_002f4128 & 1) == 0) && (iVar12 = __cxa_guard_acquire(&DAT_002f4128), iVar12 != 0)) {
      FUN_002356b8(&DAT_002f4058);
      __cxa_atexit(FUN_00168328,&DAT_002f4058,&PTR_LOOP_002d9430);
      __cxa_guard_release(&DAT_002f4128);
    }
    FUN_0015f5cc(&puStack_d8,*puVar36);
    FUN_00238558(&DAT_002f4058,&puStack_d8,0x82);
    FUN_0024fe34(&puStack_d8);
    *(undefined4 *)(puVar7 + 0x2e4) = 0x26;
    *(undefined4 *)(puVar7 + 0x2e0) = 0x128;
    iVar12 = *(int *)(puVar7 + 0x2e4);
    *(ulong *)(puVar7 + 0x128) = (ulong)uVar11;
    pcVar33 = (code *)(ulong)*(uint *)(puVar7 + 0x140);
    uVar10 = 0x39;
    *(uint *)(puVar7 + 0x110) = (uint)(uVar11 != 200);
    uVar29 = extraout_x12_00;
    uVar21 = uVar10;
    pcVar31 = extraout_x14_01;
    uVar11 = uVar10;
    if ((0xda < *(int *)(puVar7 + 0x2e0)) && ((iVar12 + iVar12 * iVar12 + 7U) % 0x51 == 0)) {
      puVar36 = (undefined8 *)0x7b;
      goto LAB_00172050;
    }
    goto LAB_00172060;
  }
  puVar39 = (undefined8 *)0x7b;
  puVar42 = (undefined8 *)0x3;
  param_7 = 0x89;
  iVar12 = (int)*(undefined8 *)(puVar7 + 0x128);
  if ((*(uint *)(puVar7 + 0x110) & 1) == 0) {
    uVar11 = 0;
  }
LAB_001723b0:
  pcVar34 = (code *)((ulong)pcVar33 & 0xffffffff);
  *(long *)(puVar7 + 0x138) = (long)iVar12;
LAB_001723c8:
  do {
    puVar36 = puVar39;
    puVar44 = puVar42;
joined_r0x001723d8:
    if ((int)param_7 != 0x89) {
      pcVar37 = (code *)0x194;
      uVar21 = *(uint *)(puVar7 + 0x128);
      puVar41 = puVar36;
      uVar10 = uVar11;
      while (puVar28 = (undefined8 *)(ulong)uVar21, uVar18 = uVar10, (int)puVar44 == 0x95) {
        while( true ) {
          *(int *)(puVar7 + 0x140) = (int)puVar28;
          uVar21 = uVar18;
          while (uVar13 = (undefined4)uVar29, (int)puVar41 == 0x8d) {
            if (uVar21 == 0x39) {
              *(undefined4 *)(puVar7 + 0x31c) = 0x71;
              *(undefined4 *)(puVar7 + 0x318) = 0x1c2;
              *(undefined4 *)(puVar7 + 0x138) = 1;
              uVar13 = 0xfa;
              iVar38 = 0x46;
              iVar12 = 0x1f;
              uVar29 = 0x89;
              puVar44 = (undefined8 *)0x3;
              uVar11 = 0x39;
              if (*(int *)(puVar7 + 0x31c) * *(int *)(puVar7 + 0x31c) * -0x5e50d794 + 0xa1af286cU <
                  0xd79435f && *(int *)(puVar7 + 0x318) < 0xfb) {
                uVar11 = 0;
              }
              iVar15 = 0x7b;
              goto LAB_00172b10;
            }
            puVar42 = *(undefined8 **)(puVar7 + 0x130);
            FUN_0015f5cc(&puStack_d8,*puVar42);
            puVar39 = (undefined8 *)&DAT_002f4058;
            FUN_00238558(&DAT_002f4058,&puStack_d8,0x98);
            FUN_0024fe34(&puStack_d8);
            pcVar31 = (code *)FUN_002424dc(*(undefined8 *)(puVar7 + 0xf8),auStack_c0);
            if (((DAT_002f4128 & 1) == 0) &&
               (iVar12 = __cxa_guard_acquire(&DAT_002f4128), iVar12 != 0)) {
              FUN_002356b8(&DAT_002f4058);
              __cxa_atexit(FUN_00168328,&DAT_002f4058,&PTR_LOOP_002d9430);
              __cxa_guard_release(&DAT_002f4128);
            }
            FUN_0015f5cc(&puStack_d8,*puVar42);
            uVar43 = 0x99;
            if (pcVar31 != (code *)0x0) {
              uVar43 = 0x9a;
            }
            FUN_00238558(&DAT_002f4058,&puStack_d8,uVar43);
            FUN_0024fe34(&puStack_d8);
            uVar13 = (undefined4)extraout_x12_04;
            uVar21 = 0x39;
            uVar29 = extraout_x12_04;
            pcVar33 = pcVar34;
            pcVar37 = pcVar31;
            if (pcVar31 == (code *)0x0) {
              *(undefined4 *)(puVar7 + 0x138) = 0;
              iVar38 = 0x46;
              iVar12 = 0x1f;
              uVar29 = 0x89;
              puVar44 = (undefined8 *)0x95;
              iVar15 = 0x8d;
              uVar11 = 0x39;
              goto LAB_00172b10;
            }
          }
          if (uVar18 != 0) break;
          pcVar37 = (code *)&DAT_002f4128;
          if (((DAT_002f4128 & 1) == 0) &&
             (iVar12 = __cxa_guard_acquire(&DAT_002f4128), iVar12 != 0)) {
            FUN_002356b8(&DAT_002f4058);
            __cxa_atexit(FUN_00168328,&DAT_002f4058,&PTR_LOOP_002d9430);
            __cxa_guard_release(&DAT_002f4128);
          }
          puVar39 = *(undefined8 **)(puVar7 + 0x130);
          FUN_0015f5cc(&puStack_d8,*puVar39);
          FUN_00238558(&DAT_002f4058,&puStack_d8,0x96);
          FUN_0024fe34(&puStack_d8);
          uVar43 = FUN_00165a74(*puVar39);
          FUN_00244ba4(auStack_c0,*(undefined8 *)(puVar7 + 0xf8),0,puVar7 + 0x4a8,uVar43);
          bVar8 = 0 < iStack_bc;
          puVar28 = (undefined8 *)(ulong)bVar8;
          uVar29 = extraout_x12_05;
          pcVar31 = extraout_x14_05;
          if (((DAT_002f4128 & 1) == 0) &&
             (iVar12 = __cxa_guard_acquire(&DAT_002f4128), uVar29 = extraout_x12_06,
             pcVar31 = extraout_x14_06, puVar39 = puVar28, iVar12 != 0)) {
            pcVar37 = (code *)&DAT_002f4058;
            FUN_002356b8(&DAT_002f4058);
            __cxa_atexit(FUN_00168328,&DAT_002f4058,&PTR_LOOP_002d9430);
            __cxa_guard_release(&DAT_002f4128);
            uVar29 = extraout_x12_07;
            pcVar31 = extraout_x14_07;
          }
          *(undefined4 *)(puVar7 + 0x314) = 0x72;
          *(undefined4 *)(puVar7 + 0x310) = 299;
          uVar18 = 0x39;
          pcVar33 = pcVar34;
          if (*(int *)(puVar7 + 0x314) * *(int *)(puVar7 + 0x314) + 1 ==
              *(int *)(puVar7 + 0x310) * *(int *)(puVar7 + 0x310) * 7) {
            *(uint *)(puVar7 + 0x128) = (uint)bVar8;
            puVar36 = (undefined8 *)0x8d;
            puVar44 = (undefined8 *)0x3;
            uVar11 = 0x39;
            goto joined_r0x001723d8;
          }
        }
        uVar10 = 0;
        puVar41 = (undefined8 *)0x8d;
        uVar21 = 1;
        if ((*(uint *)(puVar7 + 0x140) & 1) == 0) {
          iVar38 = *(int *)(puVar7 + 0xa4);
          iVar12 = 0x1f;
          puVar44 = (undefined8 *)0x3;
          uVar29 = param_7;
          uVar11 = uVar18;
          goto LAB_0017428c;
        }
      }
      puVar41 = *(undefined8 **)(puVar7 + 0x130);
LAB_00172838:
      while( true ) {
        uVar13 = (undefined4)uVar29;
        pcVar37 = (code *)0x194;
        if ((int)puVar36 == 0x8d) {
          if (uVar11 != 0) {
            uVar11 = 0;
            puVar36 = (undefined8 *)0x7b;
            puVar44 = (undefined8 *)0x95;
            puVar7 = puVar7 + 0xf80;
            goto joined_r0x001723d8;
          }
          *(undefined4 *)(puVar7 + 0x30c) = 0xda;
          *(undefined4 *)(puVar7 + 0x308) = 0x85;
          if (*(int *)(puVar7 + 0x308) < 0xd6) goto code_r0x0017286c;
          goto LAB_00172a34;
        }
        if (uVar11 != 0) break;
        if (((DAT_002f4128 & 1) == 0) && (iVar12 = __cxa_guard_acquire(&DAT_002f4128), iVar12 != 0))
        {
          FUN_002356b8(&DAT_002f4058);
          __cxa_atexit(FUN_00168328,&DAT_002f4058,&PTR_LOOP_002d9430);
          __cxa_guard_release(&DAT_002f4128);
        }
        FUN_0015f5cc(&puStack_d8,*puVar41);
        FUN_0023993c(&DAT_002f4058,&puStack_d8,*(undefined8 *)(puVar7 + 0x138));
        FUN_0024fe34(&puStack_d8);
        if (((DAT_002f4128 & 1) == 0) && (iVar12 = __cxa_guard_acquire(&DAT_002f4128), iVar12 != 0))
        {
          FUN_002356b8(&DAT_002f4058);
          __cxa_atexit(FUN_00168328,&DAT_002f4058,&PTR_LOOP_002d9430);
          __cxa_guard_release(&DAT_002f4128);
        }
        FUN_0015f5cc(&puStack_d8,*puVar41);
        FUN_00238558(&DAT_002f4058,&puStack_d8,0x8c);
        FUN_0024fe34(&puStack_d8);
        *(undefined4 *)(puVar7 + 0x304) = 0x61;
        *(undefined4 *)(puVar7 + 0x300) = 0x119;
        uVar11 = 0x39;
        uVar29 = extraout_x12_08;
        pcVar31 = extraout_x14_08;
        pcVar33 = pcVar34;
        if (*(int *)(puVar7 + 0x300) < 0x144) {
          puVar42 = (undefined8 *)0x95;
          puVar39 = (undefined8 *)0x8d;
          if ((*(int *)(puVar7 + 0x304) * *(int *)(puVar7 + 0x304) * 4 + 4U) % 0x13 == 0) {
            param_7 = 0x89;
            goto LAB_001723c8;
          }
        }
      }
      iVar38 = *(int *)(puVar7 + 0xa4);
      iVar12 = 0x77;
      uVar29 = 0x89;
LAB_0017428c:
      iVar15 = 0x8d;
LAB_00172b10:
      *(code **)(puVar7 + 0x128) = pcVar31;
      if (iVar38 != 0x46) goto LAB_00173c14;
      iVar38 = 0xb9;
LAB_00172b9c:
      *(int *)(puVar7 + 0xf4) = (int)puVar39 + 1;
      *(long *)(puVar7 + 0x120) = (long)(int)puVar39;
LAB_00172bb0:
      *(int *)(puVar7 + 0x140) = (int)pcVar33;
joined_r0x00172bc8:
      if (iVar38 != 0x14) {
        iVar19 = (int)uVar29;
joined_r0x00172bd0:
        if (iVar12 == 0x77) {
          uVar13 = 0x77;
          if ((int)uVar29 == 0x28) goto LAB_00172be0;
          puVar41 = puVar42;
          uVar21 = uVar11;
          if ((int)puVar44 == 3) {
            while( true ) {
              while (iVar15 != 0x8d) {
                *(int *)(puVar7 + 0x100) = iVar12;
                *(int *)(puVar7 + 0x10c) = iVar38;
                *(undefined8 ***)(puVar7 + 0x110) = param_5;
                if (uVar11 == 0) {
                  puVar7 = puVar7 + 0xdc0;
                }
                lVar30 = *(long *)(puVar7 + 0x128);
                uVar43 = *(undefined8 *)(lVar30 + 0x30);
                *(undefined8 *)(puVar7 + 0xe8) = *(undefined8 *)(lVar30 + 0x28);
                FUN_0024fad8(auStack_b0,uVar43);
                FUN_0024fc68(auStack_a0,*(undefined8 *)(lVar30 + 0x20));
                iVar4 = iStack_ac;
                *(undefined4 *)(puVar7 + 0x364) = 0x8f;
                *(undefined4 *)(puVar7 + 0x360) = 0x1c3;
                iVar19 = *(int *)(puVar7 + 0x364);
                pcVar33 = (code *)(ulong)*(uint *)(puVar7 + 0x140);
                param_5 = *(undefined8 ***)(puVar7 + 0x110);
                iVar38 = *(int *)(puVar7 + 0x10c);
                iVar12 = *(int *)(puVar7 + 0x100);
                puVar41 = (undefined8 *)(ulong)(0 < iVar4);
                if ((*(int *)(puVar7 + 0x360) < 0x120) ||
                   (uVar11 = 0, (iVar19 + iVar19 * iVar19 + 7U) % 0x51 != 0)) {
                  uVar11 = 0;
                  iVar15 = 0x8d;
                }
              }
              puVar42 = (undefined8 *)((ulong)puVar41 & 0xffffffff);
              if (uVar11 != 0) break;
              uVar11 = 0x39;
              uVar16 = (ulong)puVar41 & 1;
              puVar41 = (undefined8 *)0x1;
              if (uVar16 == 0) {
                puVar42 = (undefined8 *)0x0;
                iVar38 = 0x14;
                iVar15 = 0x8d;
                goto joined_r0x00172bc8;
              }
            }
            *(undefined4 *)(puVar7 + 0x36c) = 0xe1;
            *(undefined4 *)(puVar7 + 0x368) = 0x49;
            uVar21 = 0;
            iVar15 = 0x7b;
            if (*(int *)(puVar7 + 0x36c) * *(int *)(puVar7 + 0x36c) + 1 !=
                *(int *)(puVar7 + 0x368) * *(int *)(puVar7 + 0x368) * 7) {
              uVar21 = uVar11;
            }
          }
LAB_00172f18:
          while (iVar19 = iVar15, iVar15 = iStack_9c, iVar19 != 0x8d) {
            if (uVar21 != 0x39) {
              puVar7 = puVar7 + 0xa41;
            }
            *(undefined4 *)(puVar7 + 0x374) = 0x6c;
            *(undefined4 *)(puVar7 + 0x370) = 0x12f;
            puVar36 = (undefined8 *)(ulong)(0 < iVar15);
            uVar21 = 0;
            iVar15 = 0x8d;
            if ((*(int *)(puVar7 + 0x370) < 0xa2) &&
               (iVar15 = iVar19, (*(int *)(puVar7 + 0x374) * *(int *)(puVar7 + 0x374) + 1U) % 7 != 0
               )) {
              iVar15 = 0x8d;
            }
          }
          if (uVar21 == 0x39) goto LAB_00172f9c;
          uVar16 = (ulong)puVar36 & 1;
          puVar36 = (undefined8 *)0x1;
          uVar21 = 0x39;
          iVar15 = iVar19;
          if (uVar16 != 0) goto LAB_00172f18;
          puVar36 = (undefined8 *)0x0;
          puVar44 = (undefined8 *)0x3;
LAB_001733c0:
          iVar38 = 0x14;
          iVar15 = 0x8d;
          uVar11 = 0x39;
          goto joined_r0x00172bc8;
        }
        lVar30 = *(long *)(puVar7 + 0x128);
joined_r0x00172fe8:
        if (iVar19 != 0x28) {
joined_r0x00173030:
          uVar29 = param_7;
          uVar21 = uVar11;
          if ((int)puVar44 != 0x95) {
LAB_00173034:
            while (param_7 = uVar29, iVar15 == 0x7b) {
              if (uVar21 != 0x39) {
                puVar7 = puVar7 + 0x882;
              }
              param_5 = *(undefined8 ***)(lVar30 + 0x18);
              *(undefined4 *)(puVar7 + 0x324) = 0x10;
              *(undefined4 *)(puVar7 + 800) = 0x121;
              param_7 = (ulong)(0 < (long)param_5);
              if ((0x17b < *(int *)(puVar7 + 800)) ||
                 (uVar21 = 0, uVar29 = param_7,
                 (*(int *)(puVar7 + 0x324) * *(int *)(puVar7 + 0x324) + 1U) % 7 != 0))
              goto LAB_001730ac;
            }
            if (uVar21 == 0) {
              uVar11 = 0x39;
              uVar29 = 1;
              uVar21 = uVar11;
              if ((param_7 & 1) != 0) goto LAB_00173034;
            }
            else {
              *(undefined4 *)(puVar7 + 0x32c) = 0x11e;
              *(undefined4 *)(puVar7 + 0x328) = 0x129;
              iVar15 = 0x7b;
              uVar11 = 0;
              if (*(int *)(puVar7 + 0x32c) * *(int *)(puVar7 + 0x32c) + 1 !=
                  *(int *)(puVar7 + 0x328) * *(int *)(puVar7 + 0x328) * 7) {
                uVar11 = uVar21;
              }
            }
            puVar44 = (undefined8 *)0x95;
            goto joined_r0x00172fe8;
          }
          plVar32 = *(long **)(puVar7 + 0xd0);
          do {
            while (iVar12 = iVar15, uVar21 = uVar11, iVar15 = iVar12, iVar12 == 0x7b) {
              if (uVar21 == 0) {
                puVar7 = puVar7 + 0x883;
                uVar11 = 0x39;
              }
              else {
                *plVar32 = (long)param_5 * 60000;
                *(undefined4 *)(puVar7 + 0x334) = 0x18a;
                *(undefined4 *)(puVar7 + 0x330) = 0xe6;
                uVar11 = 0;
                iVar15 = 0x8d;
                if ((*(int *)(puVar7 + 0x330) < 0xae) &&
                   (iVar15 = iVar12,
                   (*(int *)(puVar7 + 0x334) * *(int *)(puVar7 + 0x334) * 4 + 4U) % 0x13 != 0)) {
                  iVar15 = 0x8d;
                }
              }
            }
            uVar11 = 0x39;
          } while (uVar21 == 0);
          *(undefined4 *)(puVar7 + 0x33c) = 0;
          *(undefined4 *)(puVar7 + 0x338) = 0x41;
          iVar12 = *(int *)(puVar7 + 0x33c);
          iVar15 = 0x7b;
          uVar11 = 0;
          if (0x329161f < (iVar12 + iVar12 * iVar12) * 0x781948b1 + 0x48b0fcd7U ||
              *(int *)(puVar7 + 0x338) < 0x87) {
            uVar11 = uVar21;
          }
          puVar44 = (undefined8 *)0x3;
        }
        uVar21 = *(uint *)(puVar7 + 0x138);
        iVar12 = (int)puVar44;
joined_r0x001732a4:
        do {
          if (iVar12 == 0x95) {
LAB_001732c4:
            do {
              if (iVar15 == 0x8d) {
                if (uVar11 == 0x39) {
                  *(undefined4 *)(puVar7 + 0x35c) = 0x14f;
                  *(undefined4 *)(puVar7 + 0x358) = 0x7e;
                  iVar15 = 0x7b;
                  puVar44 = (undefined8 *)0x3;
                  uVar29 = 0x89;
                  uVar11 = 0x39;
                  if (*(int *)(puVar7 + 0x35c) * *(int *)(puVar7 + 0x35c) * -0x49249249 +
                      0xb6db6db7U < 0x24924925 && *(int *)(puVar7 + 0x358) < 0xa2) {
                    uVar11 = 0;
                  }
                  iVar12 = 0x77;
                  goto joined_r0x00172bc8;
                }
                uVar11 = 0x39;
                if ((uVar21 & 1) == 0) {
                  *(undefined4 *)(puVar7 + 0x138) = 0;
                  iVar38 = 0x14;
                  iVar12 = 0x77;
                  uVar29 = 0x28;
                  puVar44 = (undefined8 *)0x3;
                  iVar15 = 0x8d;
                  goto LAB_00172bb0;
                }
                goto LAB_001732c4;
              }
              if (uVar11 == 0) {
                puVar7 = puVar7 + 0xd01;
                uVar11 = 0x39;
                goto LAB_001732c4;
              }
              *(undefined4 *)(puVar7 + 0x354) = 0xf5;
              *(undefined4 *)(puVar7 + 0x350) = 0xde;
              uVar11 = 0;
              iVar12 = (int)puVar44;
              if (0xbb < *(int *)(puVar7 + 0x350)) {
                iVar15 = 0x8d;
                goto joined_r0x001732a4;
              }
            } while ((*(int *)(puVar7 + 0x354) * *(int *)(puVar7 + 0x354) + 1U) % 7 == 0);
            iVar15 = 0x8d;
            goto joined_r0x001732a4;
          }
          do {
            while( true ) {
              while (iVar15 != 0x7b) {
                if (uVar11 != 0) {
                  *(undefined4 *)(puVar7 + 0x34c) = 0xbb;
                  *(undefined4 *)(puVar7 + 0x348) = 0xf8;
                  puVar44 = (undefined8 *)0x95;
                  if (*(int *)(puVar7 + 0x34c) * *(int *)(puVar7 + 0x34c) * -0x49249249 +
                      0xb6db6db7U < 0x24924925 && *(int *)(puVar7 + 0x348) < 0x6c) {
                    uVar11 = 0;
                  }
                  iVar15 = 0x7b;
                  goto LAB_001732c4;
                }
                uVar11 = 0x39;
                if (((ulong)pcVar33 & 1) == 0) {
                  pcVar33 = (code *)0x0;
                  iVar38 = 0x14;
                  iVar12 = 0x77;
                  uVar29 = 0x28;
                  puVar44 = (undefined8 *)0x95;
                  goto LAB_00172bb0;
                }
              }
              if (uVar11 != 0) break;
              puVar7 = puVar7 + 0x782;
              uVar11 = 0x39;
            }
            *(undefined4 *)(puVar7 + 0x344) = 0xa3;
            *(undefined4 *)(puVar7 + 0x340) = 0xe8;
            uVar11 = 0;
            iVar12 = (int)puVar44;
            if (0x1d < *(int *)(puVar7 + 0x340)) {
              iVar15 = 0x8d;
              goto joined_r0x001732a4;
            }
          } while ((*(int *)(puVar7 + 0x344) * *(int *)(puVar7 + 0x344) + 1U) % 7 == 0);
          iVar15 = 0x8d;
        } while( true );
      }
      pcVar31 = (code *)(ulong)(*(ulong *)(puVar7 + 0x120) < *(ulong *)(puVar7 + 0xe8));
      while (iVar12 != 0x77) {
        iVar38 = (int)puVar44;
joined_r0x001733f8:
        if ((int)uVar29 == 0x28) {
          lVar30 = *(long *)(puVar7 + 0x118);
          uVar21 = uVar11;
          goto joined_r0x00173678;
        }
        pcVar6 = (code *)((ulong)pcVar37 & 0xffffffff);
        if ((int)puVar44 != 0x95) {
LAB_0017344c:
          while (pcVar37 = pcVar6, iVar15 == 0x8d) {
            if (uVar11 == 0x39) {
              *(undefined4 *)(puVar7 + 0x3ac) = 0xcb;
              *(undefined4 *)(puVar7 + 0x3a8) = 0x7f;
              iVar15 = 0x7b;
              uVar11 = 0;
              if (*(int *)(puVar7 + 0x3ac) * *(int *)(puVar7 + 0x3ac) + 1 !=
                  *(int *)(puVar7 + 0x3a8) * *(int *)(puVar7 + 0x3a8) * 7) {
                uVar11 = 0x39;
              }
              goto LAB_00173434;
            }
            uVar11 = 0x39;
            pcVar6 = (code *)0x0;
            if (((ulong)pcVar37 & 1) != 0) goto LAB_001734ec;
          }
          if (uVar11 == 0) {
            puVar7 = puVar7 + 0xf80;
          }
          *(undefined4 *)(puVar7 + 0x3a4) = 0x8c;
          *(undefined4 *)(puVar7 + 0x3a0) = 0x1ab;
          iVar38 = *(int *)(puVar7 + 0x3a4);
          pcVar6 = pcVar31;
          if (0x103 < *(int *)(puVar7 + 0x3a0)) {
            uVar11 = 0;
            *(undefined8 *)(puVar7 + 0x118) = *(undefined8 *)(puVar7 + 0x120);
            if ((iVar38 + iVar38 * iVar38 + 7U) % 0x51 == 0) goto LAB_0017344c;
          }
          uVar11 = 0;
          iVar15 = 0x8d;
          *(undefined8 *)(puVar7 + 0x118) = *(undefined8 *)(puVar7 + 0x120);
          if ((int)puVar44 == 0x95) {
            *(undefined8 *)(puVar7 + 0x118) = *(undefined8 *)(puVar7 + 0x120);
            pcVar37 = pcVar31;
            goto LAB_00173500;
          }
          goto LAB_0017344c;
        }
LAB_00173500:
        *(int *)(puVar7 + 0x110) = (int)pcVar31;
        uVar21 = uVar11;
        if (iVar15 == 0x7b) {
          while( true ) {
            while (uVar21 == 0) {
              puVar7 = puVar7 + 0x682;
              uVar21 = 0x39;
            }
            FUN_00234e00(&DAT_002f4230,auStack_a0,auStack_b0);
            *(undefined4 *)(puVar7 + 0x3b4) = 0x114;
            *(undefined4 *)(puVar7 + 0x3b0) = 0x75;
            uVar21 = 0;
            uVar11 = 0;
            iVar15 = 0x8d;
            if (0x19c < *(int *)(puVar7 + 0x3b0)) break;
            pcVar33 = (code *)(ulong)*(uint *)(puVar7 + 0x140);
            if ((*(int *)(puVar7 + 0x3b4) * *(int *)(puVar7 + 0x3b4) + 1U) % 7 != 0)
            goto LAB_00173514;
          }
          pcVar33 = (code *)(ulong)*(uint *)(puVar7 + 0x140);
LAB_0017363c:
          uVar11 = 0x39;
          puVar44 = (undefined8 *)0x95;
        }
        else {
LAB_00173514:
          if (uVar11 != 0x39) goto LAB_0017363c;
          *(undefined4 *)(puVar7 + 0x3bc) = 0x117;
          *(undefined4 *)(puVar7 + 0x3b8) = 0x11c;
          iVar15 = 0x7b;
          uVar11 = 0x39;
          if (*(int *)(puVar7 + 0x3bc) * *(int *)(puVar7 + 0x3bc) * -0x49249249 + 0xb6db6db7U <
              0x24924925 && *(int *)(puVar7 + 0x3b8) < 0x172) {
            uVar11 = 0;
          }
          puVar44 = (undefined8 *)0x3;
        }
        pcVar31 = (code *)(ulong)*(uint *)(puVar7 + 0x110);
        uVar29 = 0x28;
      }
      goto LAB_00173874;
    }
LAB_001723e4:
    puVar42 = puVar44;
    puVar41 = puVar36;
    uVar21 = uVar11;
    while (uVar11 = uVar21, uVar21 = uVar11, (int)puVar42 != 0x95) {
      while( true ) {
        while ((int)puVar41 != 0x7b) {
          if (uVar11 == 0) {
            puVar7 = puVar7 + 0xc00;
            uVar11 = 0x39;
          }
          else {
            if (((DAT_002f4020 & 1) == 0) &&
               (iVar12 = __cxa_guard_acquire(&DAT_002f4020), iVar12 != 0)) {
              DAT_002f3ff8 = &PTR_FUN_002d9c90;
              DAT_002f4014 = *(undefined4 *)(puVar7 + 0x4c);
              DAT_002f4000 = 0;
              DAT_002f4008 = 0;
              DAT_002f4010 = 0;
              DAT_002f4018 = DAT_002f4014;
              __cxa_guard_release(&DAT_002f4020);
            }
            FUN_00231ab0(&DAT_002f3ff8);
            *(undefined4 *)(puVar7 + 0x2f4) = 0x1bd;
            *(undefined4 *)(puVar7 + 0x2f0) = 0x32;
            iVar12 = *(int *)(puVar7 + 0x2f4);
            uVar11 = 0;
            puVar36 = (undefined8 *)0x7b;
            uVar29 = extraout_x12_02;
            pcVar31 = extraout_x14_03;
            pcVar33 = pcVar34;
            puVar44 = (undefined8 *)0x95;
            if ((*(int *)(puVar7 + 0x2f0) < 0x189) || ((iVar12 + iVar12 * iVar12 + 7U) % 0x51 != 0))
            goto LAB_001723e4;
          }
        }
        if (uVar11 != 0) break;
        uVar11 = 0x39;
        if (*(int *)(puVar7 + 0x4ac) != 0) {
          uVar16 = FUN_00250660(puVar7 + 0x4a8,&DAT_0029bb7e);
          uVar11 = 0x39;
          uVar29 = extraout_x12_01;
          pcVar31 = extraout_x14_02;
          pcVar33 = pcVar34;
          if ((uVar16 & 1) == 0) {
            uVar11 = 0;
            param_7 = 0x28;
            puVar39 = (undefined8 *)0x8d;
            goto LAB_001723c8;
          }
        }
      }
      *(undefined4 *)(puVar7 + 0x2ec) = 0x1ac;
      *(undefined4 *)(puVar7 + 0x2e8) = 0x18e;
      puVar41 = (undefined8 *)0x8d;
      uVar21 = 0;
      if (*(int *)(puVar7 + 0x2ec) * *(int *)(puVar7 + 0x2ec) + 1 !=
          *(int *)(puVar7 + 0x2e8) * *(int *)(puVar7 + 0x2e8) * 7) {
        uVar21 = uVar11;
      }
    }
LAB_00172528:
    do {
      uVar11 = uVar21;
      if ((int)puVar41 != 0x8d) {
        if (uVar11 == 0) {
          uVar21 = 0x39;
          if (((ulong)pcVar33 & 1) != 0) goto LAB_00172528;
        }
        else {
          FUN_00235090(&DAT_002f4230);
          uVar29 = extraout_x12_03;
          pcVar31 = extraout_x14_04;
          pcVar33 = pcVar34;
        }
        puVar41 = (undefined8 *)0x8d;
        uVar21 = 0;
        goto LAB_00172528;
      }
      if (uVar11 == 0x39) {
        uVar11 = 0;
        puVar7 = puVar7 + 0xe83;
        param_7 = 0x28;
        puVar42 = (undefined8 *)0x3;
        puVar39 = (undefined8 *)0x7b;
        goto LAB_001723c8;
      }
      *(undefined4 *)(puVar7 + 0x2fc) = 0x194;
      *(undefined4 *)(puVar7 + 0x2f8) = 0x173;
      iVar12 = *(int *)(puVar7 + 0x2fc);
      param_7 = 0x28;
      puVar39 = (undefined8 *)0x7b;
      if (*(int *)(puVar7 + 0x2f8) < 0x105) {
        puVar42 = (undefined8 *)0x3;
        goto LAB_001723c8;
      }
      uVar21 = 0x39;
    } while ((iVar12 + iVar12 * iVar12 + 7U) % 0x51 == 0);
    puVar42 = (undefined8 *)0x3;
  } while( true );
code_r0x0017286c:
  uVar29 = 0x13;
  uVar11 = 0x39;
  if ((*(int *)(puVar7 + 0x30c) * *(int *)(puVar7 + 0x30c) * 4 + 4U) % 0x13 != 0) goto LAB_00172a34;
  goto LAB_00172838;
LAB_00172a34:
  uVar11 = 0;
  puVar36 = (undefined8 *)0x7b;
  puVar44 = (undefined8 *)0x95;
  goto joined_r0x001723d8;
LAB_001730ac:
  uVar11 = 0;
  iVar15 = 0x8d;
  goto joined_r0x00173030;
LAB_00172be0:
  while (uVar21 = uVar11, (int)puVar44 != 0x95) {
LAB_00172c74:
    while (iVar15 != 0x8d) {
      *(undefined4 *)(puVar7 + 0x100) = uVar13;
      *(int *)(puVar7 + 0x10c) = iVar38;
      *(undefined8 ***)(puVar7 + 0x110) = param_5;
      if (uVar21 != 0x39) {
        puVar7 = puVar7 + 0x880;
      }
      FUN_0015f5cc(auStack_90,**(undefined8 **)(puVar7 + 0x130));
      pcVar34 = (code *)FUN_00250644(auStack_90,auStack_a0);
      *(undefined4 *)(puVar7 + 900) = 0x35;
      *(undefined4 *)(puVar7 + 0x380) = 0x187;
      uVar21 = 0;
      if (0xed < *(int *)(puVar7 + 0x380)) {
        pcVar33 = (code *)(ulong)*(uint *)(puVar7 + 0x140);
        param_5 = *(undefined8 ***)(puVar7 + 0x110);
        iVar38 = *(int *)(puVar7 + 0x10c);
        uVar13 = *(undefined4 *)(puVar7 + 0x100);
        iVar15 = 0x8d;
        break;
      }
      pcVar33 = (code *)(ulong)*(uint *)(puVar7 + 0x140);
      param_5 = *(undefined8 ***)(puVar7 + 0x110);
      iVar38 = *(int *)(puVar7 + 0x10c);
      uVar13 = *(undefined4 *)(puVar7 + 0x100);
      uVar21 = 0;
      if ((*(int *)(puVar7 + 900) * *(int *)(puVar7 + 900) + 1U) % 7 != 0) {
        iVar15 = 0x8d;
      }
    }
    pcVar31 = (code *)((ulong)pcVar34 & 0xffffffff);
    if (uVar21 == 0) {
      uVar16 = (ulong)pcVar34 & 1;
      pcVar34 = (code *)0x1;
      uVar21 = 0x39;
      if (uVar16 == 0) {
        pcVar34 = (code *)0x0;
        iVar12 = 0x1f;
        goto LAB_001733c0;
      }
      goto LAB_00172c74;
    }
    *(undefined4 *)(puVar7 + 0x38c) = 0x16d;
    *(undefined4 *)(puVar7 + 0x388) = 0x1aa;
    puVar44 = (undefined8 *)0x95;
    iVar15 = 0x7b;
    pcVar34 = pcVar31;
    uVar11 = 0;
    if (*(int *)(puVar7 + 0x38c) * *(int *)(puVar7 + 0x38c) + 1 !=
        *(int *)(puVar7 + 0x388) * *(int *)(puVar7 + 0x388) * 7) {
      uVar11 = uVar21;
    }
  }
LAB_00172be8:
  puVar44 = (undefined8 *)((ulong)puVar39 & 0xffffffff);
  while (puVar39 = puVar44, iVar15 != 0x7b) {
    bVar8 = uVar11 == 0x39;
    uVar11 = 0x39;
    puVar44 = (undefined8 *)0x0;
    if (bVar8) {
      *(undefined4 *)(puVar7 + 0x39c) = 0x1f7;
      *(undefined4 *)(puVar7 + 0x398) = 0x1e9;
      iVar15 = *(int *)(puVar7 + 0x39c);
      iVar38 = 0x14;
      iVar12 = 0x1f;
      uVar29 = 0x89;
      puVar44 = (undefined8 *)0x3;
      uVar11 = 0;
      if (0x329161f < (iVar15 + iVar15 * iVar15) * 0x781948b1 + 0x48b0fcd7U ||
          *(int *)(puVar7 + 0x398) < 7) {
        uVar11 = 0x39;
      }
      iVar15 = 0x7b;
      goto LAB_00172b9c;
    }
  }
  if (uVar11 == 0x39) goto LAB_00172c20;
  do {
    puVar7 = puVar7 + 0xf81;
LAB_00172c20:
    *(undefined4 *)(puVar7 + 0x394) = 0x1d9;
    *(undefined4 *)(puVar7 + 0x390) = 0x13b;
  } while ((*(int *)(puVar7 + 0x390) < 0x41) &&
          ((*(int *)(puVar7 + 0x394) * *(int *)(puVar7 + 0x394) + 1U) % 7 == 0));
  uVar11 = 0;
  iVar15 = 0x8d;
  goto LAB_00172be8;
LAB_00172f9c:
  *(undefined4 *)(puVar7 + 0x37c) = 0x12f;
  *(undefined4 *)(puVar7 + 0x378) = 0xe4;
  uVar29 = 0x28;
  iVar19 = 0x28;
  puVar44 = (undefined8 *)0x3;
  uVar11 = 0;
  if (*(int *)(puVar7 + 0x37c) * *(int *)(puVar7 + 0x37c) + 1 !=
      *(int *)(puVar7 + 0x378) * *(int *)(puVar7 + 0x378) * 7) {
    uVar11 = 0x39;
  }
  iVar15 = 0x7b;
  goto joined_r0x00172bd0;
joined_r0x00173678:
  uVar10 = uVar21;
  if (iVar38 == 0x95) goto LAB_00173794;
  do {
    if (iVar15 != 0x7b) {
      puVar39 = (undefined8 *)(ulong)*(uint *)(puVar7 + 0xe0);
      iVar38 = 0xb9;
      iVar12 = 0x77;
      uVar29 = 0x28;
      puVar44 = (undefined8 *)0x95;
      uVar11 = 0x39;
      if (uVar10 != 0x39) goto joined_r0x00172bc8;
      *(undefined4 *)(puVar7 + 0x3cc) = 0x1fb;
      *(undefined4 *)(puVar7 + 0x3c8) = 0xf0;
      if (*(int *)(puVar7 + 0x3cc) * *(int *)(puVar7 + 0x3cc) * -0x5e50d794 + 0xa1af286cU <
          0xd79435f && *(int *)(puVar7 + 0x3c8) < 0x1bc) {
        uVar21 = 0;
      }
      iVar15 = 0x7b;
      goto LAB_00173794;
    }
    if (uVar10 != 0x39) {
      puVar7 = puVar7 + 0x5c1;
    }
    *(byte *)(lStack_a8 + lVar30) = *(byte *)(lStack_a8 + lVar30) ^ 0x51;
    *(undefined4 *)(puVar7 + 0x3c4) = 0x123;
    *(undefined4 *)(puVar7 + 0x3c0) = 0x1a7;
    iVar12 = *(int *)(puVar7 + 0x3c4);
  } while ((0x181 < *(int *)(puVar7 + 0x3c0)) &&
          (uVar10 = 0, (iVar12 + iVar12 * iVar12 + 7U) % 0x51 == 0));
  uVar21 = 0;
  iVar15 = 0x8d;
  *(undefined4 *)(puVar7 + 0xe0) = *(undefined4 *)(puVar7 + 0xf4);
  goto joined_r0x00173678;
LAB_00173794:
  if (iVar15 != 0x8d) goto LAB_001737c8;
LAB_001737b0:
  bVar8 = uVar21 != 0x39;
  uVar21 = 0x39;
  if (bVar8) {
    do {
      while( true ) {
        if (iVar15 == 0x8d) goto LAB_001737b0;
LAB_001737c8:
        if (uVar21 == 0x39) break;
        puVar7 = puVar7 + 0x5c3;
        uVar21 = 0x39;
      }
      FUN_002352d0(&DAT_002f4230);
      *(undefined4 *)(puVar7 + 0x3d4) = 0xc9;
      *(undefined4 *)(puVar7 + 0x3d0) = 0xf6;
      uVar21 = 0;
    } while (*(int *)(puVar7 + 0x3d4) * *(int *)(puVar7 + 0x3d4) + 1 ==
             *(int *)(puVar7 + 0x3d0) * *(int *)(puVar7 + 0x3d0) * 7);
    iVar15 = 0x8d;
    goto LAB_001737b0;
  }
  *(undefined4 *)(puVar7 + 0x3dc) = 0x181;
  *(undefined4 *)(puVar7 + 0x3d8) = 0xed;
  uVar29 = 0x89;
  puVar44 = (undefined8 *)0x3;
  uVar11 = 0x39;
  if (*(int *)(puVar7 + 0x3dc) * *(int *)(puVar7 + 0x3dc) * -0x5e50d794 + 0xa1af286cU < 0xd79435f &&
      *(int *)(puVar7 + 0x3d8) < 0x173) {
    uVar11 = 0;
  }
  iVar15 = 0x7b;
LAB_00173874:
  pcVar37 = (code *)0x70;
LAB_00173898:
  do {
    uVar21 = uVar11;
    iVar12 = iVar15;
    if ((int)uVar29 != 0x89) goto LAB_001739bc;
    while( true ) {
      while (iVar15 = iVar12, (int)puVar44 == 0x95) {
        do {
          while( true ) {
            while (iVar15 == 0x8d) {
              bVar8 = uVar21 == 0x39;
              uVar21 = 0x39;
              if (bVar8) {
                *(undefined4 *)(puVar7 + 0x3fc) = 0x73;
                *(undefined4 *)(puVar7 + 0x3f8) = 0x38;
                uVar29 = 0x28;
                puVar44 = (undefined8 *)0x3;
                uVar11 = 0x39;
                if (*(int *)(puVar7 + 0x3fc) * *(int *)(puVar7 + 0x3fc) * -0x5e50d794 + 0xa1af286cU
                    < 0xd79435f && *(int *)(puVar7 + 0x3f8) < 0xc9) {
                  uVar11 = 0;
                }
                iVar15 = 0x7b;
                goto LAB_00173898;
              }
            }
            if (uVar21 == 0x39) break;
            puVar7 = puVar7 + 0xc42;
            uVar21 = 0x39;
          }
          FUN_002351c8(&DAT_002f4230);
          *(undefined4 *)(puVar7 + 0x3f4) = 0x113;
          *(undefined4 *)(puVar7 + 0x3f0) = 0x15c;
          uVar21 = 0;
          iVar12 = 0x8d;
        } while ((*(int *)(puVar7 + 0x3f0) < 0x11c) &&
                ((*(int *)(puVar7 + 0x3f4) * *(int *)(puVar7 + 0x3f4) * 4 + 4U) % 0x13 == 0));
      }
      if (iVar15 != 0x7b) break;
      if (uVar21 == 0) goto LAB_00173964;
      while( true ) {
        FUN_0024fe34(auStack_90);
        *(undefined4 *)(puVar7 + 0x3e4) = 0x163;
        *(undefined4 *)(puVar7 + 0x3e0) = 0x1fe;
        iVar38 = *(int *)(puVar7 + 0x3e4);
        uVar21 = 0;
        iVar12 = 0x8d;
        if ((*(int *)(puVar7 + 0x3e0) < 0x134) || ((iVar38 + iVar38 * iVar38 + 7U) % 0x51 != 0))
        break;
LAB_00173964:
        puVar7 = puVar7 + 0x700;
      }
    }
    uVar11 = 0x39;
    puVar44 = (undefined8 *)0x95;
  } while (uVar21 == 0);
  *(undefined4 *)(puVar7 + 0x3ec) = 0x4d;
  *(undefined4 *)(puVar7 + 1000) = 0x1ff;
  iVar12 = *(int *)(puVar7 + 0x3ec);
  uVar11 = 0;
  if (0x329161f < (iVar12 + iVar12 * iVar12) * 0x781948b1 + 0x48b0fcd7U ||
      *(int *)(puVar7 + 1000) < 0xe7) {
    uVar11 = uVar21;
  }
  goto LAB_00173bbc;
LAB_001734ec:
  iVar15 = 0x8d;
LAB_00173434:
  puVar44 = (undefined8 *)0x95;
  iVar38 = 0x95;
  goto joined_r0x001733f8;
LAB_001739bc:
  iVar15 = iVar12;
  uVar21 = uVar11;
  if ((int)puVar44 == 0x95) {
    do {
      while (uVar11 = uVar21, iVar15 == 0x7b) {
        if (uVar11 == 0) {
          puVar7 = puVar7 + 0x6c1;
          uVar21 = 0x39;
        }
        else {
          FUN_002351c8(&DAT_002f4230);
          *(undefined4 *)(puVar7 + 0x414) = 0x1ab;
          *(undefined4 *)(puVar7 + 0x410) = 0x1e;
          uVar11 = 0;
          iVar12 = 0x8d;
          if ((0x139 < *(int *)(puVar7 + 0x410)) ||
             (uVar21 = uVar11, (*(int *)(puVar7 + 0x414) * *(int *)(puVar7 + 0x414) + 1U) % 7 != 0))
          goto LAB_001739bc;
        }
      }
      uVar21 = 0x39;
    } while (uVar11 == 0);
    *(undefined4 *)(puVar7 + 0x41c) = 0x10c;
    *(undefined4 *)(puVar7 + 0x418) = 0xac;
    uVar13 = 0xb5;
    iVar12 = 0x1f;
    uVar29 = 0x89;
    puVar44 = (undefined8 *)0x3;
    if (*(int *)(puVar7 + 0x41c) * *(int *)(puVar7 + 0x41c) * -0x5e50d794 + 0xa1af286cU < 0xd79435f
        && *(int *)(puVar7 + 0x418) < 0xb6) {
      uVar11 = 0;
    }
    iVar15 = 0x7b;
LAB_00173c14:
    iVar38 = (int)puVar44;
    if (iVar12 == 0x77) {
      if (iVar38 != 0x95) goto LAB_00173c24;
LAB_001741ac:
      if (iVar15 != 0x7b) goto LAB_00174238;
LAB_001741b4:
      puVar17 = puVar7 + 0x488;
      do {
        while (uVar11 == 0) {
          puVar7 = puVar7 + 0xf82;
          uVar11 = 0x39;
        }
        FUN_0024fe34(auStack_e8);
        FUN_00207fd8(puVar7 + 0x4b8);
        FUN_0024fe34(puVar7 + 0x4a8);
        FUN_0024fe34(puVar7 + 0x498);
        *(undefined ***)(puVar7 + 0x478) = &PTR_FUN_002da098;
        FUN_0024fe34(puVar17);
        *(undefined4 *)(puVar7 + 0x474) = 0x1a7;
        *(undefined4 *)(puVar7 + 0x470) = 0x129;
        uVar11 = 0;
      } while (*(int *)(puVar7 + 0x474) * *(int *)(puVar7 + 0x474) + 1 ==
               *(int *)(puVar7 + 0x470) * *(int *)(puVar7 + 0x470) * 7);
LAB_00174238:
      if (*(long *)(*(long *)(puVar7 + 0x98) + 0x28) == local_80) {
        return (code *)(ulong)(*(uint *)(puVar7 + 0x140) & 1);
      }
                    /* WARNING: Subroutine does not return */
      __stack_chk_fail();
    }
    if ((int)uVar29 != 0x28) goto LAB_00174004;
LAB_00173e28:
    do {
joined_r0x00173e2c:
      if ((int)puVar44 != 3) {
        pcVar37 = (code *)((ulong)pcVar37 & 0xffffffff);
        uVar21 = uVar11;
        do {
          uVar11 = uVar21;
          uVar13 = SUB84(pcVar37,0);
          if (iVar15 != 0x8d) goto LAB_00173f08;
          pcVar37 = (code *)0x0;
          uVar21 = 0x39;
        } while (uVar11 == 0);
        *(undefined4 *)(puVar7 + 0x45c) = 0xe1;
        *(undefined4 *)(puVar7 + 0x458) = 0x1a6;
        iVar15 = 0x7b;
        if (*(int *)(puVar7 + 0x45c) * *(int *)(puVar7 + 0x45c) * -0x49249249 + 0xb6db6db7U <
            0x24924925 && *(int *)(puVar7 + 0x458) < 0xe4) {
          uVar11 = 0;
        }
        iVar38 = 3;
LAB_00173c24:
        *(undefined4 *)(puVar7 + 0x138) = uVar13;
        *(undefined4 *)(puVar7 + 0x140) = 0;
        uVar21 = uVar11;
        iVar12 = iVar15;
LAB_00173c60:
        uVar13 = *(undefined4 *)(puVar7 + 0x140);
        do {
          uVar11 = uVar21;
          puVar39 = *(undefined8 **)(puVar7 + 0x130);
          *(undefined4 *)(puVar7 + 0x140) = uVar13;
          uVar21 = uVar11;
          while (iVar12 != 0x8d) {
            if (uVar21 != 0x39) {
              puVar7 = puVar7 + 0x803;
            }
            if (((DAT_002f4020 & 1) == 0) &&
               (iVar15 = __cxa_guard_acquire(&DAT_002f4020), iVar15 != 0)) {
              DAT_002f4008 = 0;
              DAT_002f3ff8 = &PTR_FUN_002d9c90;
              DAT_002f4000 = 0;
              DAT_002f4014 = *(undefined4 *)(puVar7 + 0x4c);
              DAT_002f4010 = 0;
              DAT_002f4018 = DAT_002f4014;
              __cxa_guard_release(&DAT_002f4020);
            }
            FUN_00231e7c(&DAT_002f3ff8);
            if (((DAT_002f4020 & 1) == 0) &&
               (iVar15 = __cxa_guard_acquire(&DAT_002f4020), iVar15 != 0)) {
              DAT_002f3ff8 = &PTR_FUN_002d9c90;
              DAT_002f4014 = *(undefined4 *)(puVar7 + 0x4c);
              DAT_002f4000 = 0;
              DAT_002f4008 = 0;
              DAT_002f4010 = 0;
              DAT_002f4018 = DAT_002f4014;
              __cxa_guard_release(&DAT_002f4020);
            }
            FUN_0015f584(&puStack_d8,*puVar39);
            uVar13 = FUN_001611ec(*puVar39);
            uVar14 = FUN_0015f65c(*puVar39);
            FUN_00233400(&DAT_002f3ff8,&puStack_d8,uVar13,uVar14);
            FUN_0024fe34(&puStack_d8);
            FUN_0024fe34(auStack_c0);
            *(undefined4 *)(puVar7 + 0x464) = 0x5c;
            *(undefined4 *)(puVar7 + 0x460) = 0x153;
            if ((0x38 < *(int *)(puVar7 + 0x460)) ||
               (uVar21 = 0,
               (*(int *)(puVar7 + 0x464) * *(int *)(puVar7 + 0x464) * 4 + 4U) % 0x13 != 0)) {
              uVar11 = 0;
              uVar21 = 0;
              iVar12 = 0x8d;
              iVar15 = 0x8d;
              if (iVar38 == 0x95) goto LAB_001741ac;
              goto LAB_00173c60;
            }
          }
          uVar13 = *(undefined4 *)(puVar7 + 0x138);
          uVar21 = 0x39;
          if (uVar11 != 0) {
            *(undefined4 *)(puVar7 + 0x46c) = 0x29;
            *(undefined4 *)(puVar7 + 0x468) = 0x130;
            if (*(int *)(puVar7 + 0x46c) * *(int *)(puVar7 + 0x46c) * -0x49249249 + 0xb6db6db7U <
                0x24924925 && *(int *)(puVar7 + 0x468) < 0x2e) {
              uVar11 = 0;
            }
            goto LAB_001741b4;
          }
        } while( true );
      }
      if (iVar15 == 0x7b) {
        do {
          while (uVar11 != 0x39) {
            puVar7 = puVar7 + 0xf03;
            uVar11 = 0x39;
          }
          *(undefined4 *)(puVar7 + 0x444) = 0x1fc;
          *(undefined4 *)(puVar7 + 0x440) = 0x125;
          uVar11 = 0;
        } while (*(int *)(puVar7 + 0x444) * *(int *)(puVar7 + 0x444) + 1 ==
                 *(int *)(puVar7 + 0x440) * *(int *)(puVar7 + 0x440) * 7);
        iVar15 = 0x8d;
LAB_00173ecc:
        uVar11 = 0x39;
        pcVar37 = (code *)0x1;
      }
      else {
        if (uVar11 == 0) goto LAB_00173ecc;
        *(undefined4 *)(puVar7 + 0x44c) = 0x1ed;
        *(undefined4 *)(puVar7 + 0x448) = 0x91;
        if (*(int *)(puVar7 + 0x44c) * *(int *)(puVar7 + 0x44c) * -0x49249249 + 0xb6db6db7U <
            0x24924925 && *(int *)(puVar7 + 0x448) < 0x1f5) {
          uVar11 = 0;
        }
        iVar15 = 0x7b;
      }
      puVar44 = (undefined8 *)0x95;
    } while ((int)uVar29 == 0x28);
LAB_00174004:
    uVar21 = *(uint *)(puVar7 + 0x138);
LAB_00174008:
    do {
      iVar12 = iVar15;
      uVar10 = uVar11;
      if ((int)puVar44 != 0x95) {
        do {
          while( true ) {
            while (iVar12 == 0x8d) {
              if (uVar11 == 0x39) {
                *(undefined4 *)(puVar7 + 0x42c) = 0xf8;
                *(undefined4 *)(puVar7 + 0x428) = 0x1e8;
                puVar44 = (undefined8 *)0x95;
                uVar11 = 0;
                iVar15 = 0x7b;
                if (*(int *)(puVar7 + 0x42c) * *(int *)(puVar7 + 0x42c) + 1 !=
                    *(int *)(puVar7 + 0x428) * *(int *)(puVar7 + 0x428) * 7) {
                  uVar11 = 0x39;
                }
                goto LAB_00174008;
              }
              uVar11 = 0x39;
              if ((uVar21 & 1) == 0) {
                puVar44 = (undefined8 *)0x95;
                iVar15 = 0x8d;
                goto LAB_00174008;
              }
            }
            if (uVar11 == 0x39) break;
            puVar7 = puVar7 + 0xe02;
            uVar11 = 0x39;
          }
          *(undefined4 *)(puVar7 + 0x424) = 0xaa;
          *(undefined4 *)(puVar7 + 0x420) = 0x1e9;
          uVar11 = 0;
        } while (*(int *)(puVar7 + 0x424) * *(int *)(puVar7 + 0x424) + 1 ==
                 *(int *)(puVar7 + 0x420) * *(int *)(puVar7 + 0x420) * 7);
        iVar15 = 0x8d;
        goto LAB_00174008;
      }
      do {
        while( true ) {
          while (uVar11 = uVar10, iVar12 != 0x7b) {
            uVar10 = 0x39;
            if (uVar11 != 0) {
              *(undefined4 *)(puVar7 + 0x43c) = 0x51;
              *(undefined4 *)(puVar7 + 0x438) = 0x18d;
              uVar29 = 0x28;
              puVar44 = (undefined8 *)0x3;
              if (*(int *)(puVar7 + 0x43c) * *(int *)(puVar7 + 0x43c) * -0x5e50d794 + 0xa1af286cU <
                  0xd79435f && *(int *)(puVar7 + 0x438) < 0x1cb) {
                uVar11 = 0;
              }
              iVar15 = 0x7b;
              goto LAB_00173e28;
            }
          }
          if (uVar11 != 0) break;
          puVar7 = puVar7 + 0xb83;
          uVar10 = 0x39;
        }
        FUN_00242644(*(undefined8 *)(puVar7 + 0xf8),*(undefined8 *)(puVar7 + 0x128));
        *(undefined4 *)(puVar7 + 0x434) = 0x76;
        *(undefined4 *)(puVar7 + 0x430) = 0xfb;
        uVar11 = 0;
        iVar15 = 0x8d;
        if (0x119 < *(int *)(puVar7 + 0x430)) {
          uVar21 = *(uint *)(puVar7 + 0x138);
          break;
        }
        uVar21 = *(uint *)(puVar7 + 0x138);
        uVar10 = uVar11;
      } while ((*(int *)(puVar7 + 0x434) * *(int *)(puVar7 + 0x434) * 4 + 4U) % 0x13 == 0);
    } while( true );
  }
  if (iVar15 == 0x7b) {
    do {
      while (uVar11 == 0) {
        puVar7 = puVar7 + 0xc00;
        uVar11 = 0x39;
      }
      FUN_0024fe34(auStack_a0);
      FUN_0024fe34(auStack_b0);
      *(undefined4 *)(puVar7 + 0x404) = 0x15b;
      *(undefined4 *)(puVar7 + 0x400) = 0x70;
      iVar38 = *(int *)(puVar7 + 0x404);
      uVar11 = 0;
      iVar12 = 0x8d;
    } while ((0x1f0 < *(int *)(puVar7 + 0x400)) && ((iVar38 + iVar38 * iVar38 + 7U) % 0x51 == 0));
    goto LAB_001739bc;
  }
  puVar44 = (undefined8 *)0x95;
  bVar8 = uVar11 == 0x39;
  uVar11 = 0x39;
  if (bVar8) {
    *(undefined4 *)(puVar7 + 0x40c) = 0x6b;
    *(undefined4 *)(puVar7 + 0x408) = 0xe1;
    uVar11 = 0x39;
    if (*(int *)(puVar7 + 0x40c) * *(int *)(puVar7 + 0x40c) * -0x5e50d794 + 0xa1af286cU < 0xd79435f
        && *(int *)(puVar7 + 0x408) < 0x129) {
      uVar11 = 0;
    }
LAB_00173bbc:
    iVar15 = 0x7b;
    puVar44 = (undefined8 *)0x95;
  }
  goto LAB_00173898;
LAB_00173f08:
  puVar39 = *(undefined8 **)(puVar7 + 0x130);
  if (uVar11 != 0) goto LAB_00173f28;
  do {
    puVar7 = puVar7 + 0xc00;
LAB_00173f28:
    FUN_0015f5cc(&puStack_d8,*puVar39);
    FUN_00238558(&DAT_002f4058,&puStack_d8,0x97);
    FUN_0024fe34(&puStack_d8);
    *(undefined4 *)(puVar7 + 0x454) = 0x1b9;
    *(undefined4 *)(puVar7 + 0x450) = 0x1a7;
  } while ((*(int *)(puVar7 + 0x450) < 0x7a) &&
          ((*(int *)(puVar7 + 0x454) * *(int *)(puVar7 + 0x454) + 1U) % 7 == 0));
  uVar11 = 0;
  iVar15 = 0x8d;
  goto joined_r0x00173e2c;
code_r0x001719b8:
  *(undefined4 *)(puVar7 + 0x29c) = 0x42;
  *(undefined4 *)(puVar7 + 0x298) = 0x192;
  uVar11 = 0x39;
  if ((0x1e4 < *(int *)(puVar7 + 0x298)) ||
     ((*(int *)(puVar7 + 0x29c) * *(int *)(puVar7 + 0x29c) * 4 + 4U) % 0x13 != 0)) {
LAB_0017197c:
    puVar42 = (undefined8 *)0x95;
    puVar39 = (undefined8 *)0x7b;
    pcVar34 = pcVar33;
    goto LAB_00171984;
  }
  goto LAB_001719a4;
LAB_0017088c:
  *(uint *)(puVar7 + 0xb0) = uVar21;
  puVar39 = (undefined8 *)0x8d;
  uVar11 = 0x39;
LAB_00170978:
  pcVar34 = param_1;
  uVar21 = uVar11;
LAB_00170984:
  if ((int)puVar39 == 0x8d) {
    if (uVar21 == 0) goto code_r0x00170990;
    puVar7 = puVar7 + 0xa81;
    goto LAB_00170a3c;
  }
  if (uVar11 == 0x39) {
    *(char **)(puVar7 + 0x68) = pcVar27;
    puVar42 = (undefined8 *)0x95;
    iVar38 = 0x46;
    *(code **)(puVar7 + 0x138) = param_1;
    *(undefined4 *)(puVar7 + 0x30) = *(undefined4 *)(puVar7 + 0xc);
LAB_00170d60:
    uVar29 = 0xb9;
    uVar26 = *(undefined8 *)(puVar7 + 200);
  }
  else {
    *(undefined4 *)(puVar7 + 0x1c4) = 0xdd;
    *(undefined4 *)(puVar7 + 0x1c0) = 0x1d;
    iVar38 = *(int *)(puVar7 + 0x1c4);
    pcVar31 = (code *)(ulong)*(uint *)(puVar7 + 0x1c0);
    uVar11 = 0x39;
    *(int *)(puVar7 + 0xc) = iVar15;
    if ((int)*(uint *)(puVar7 + 0x1c0) < 0x139) goto LAB_00170978;
    pcVar33 = (code *)0x51;
    puVar42 = (undefined8 *)0x95;
    uVar21 = (iVar38 + iVar38 * iVar38 + 7U) % 0x51;
    pcVar31 = (code *)(ulong)uVar21;
    uVar29 = 0xb9;
    *(int *)(puVar7 + 0xc) = iVar15;
    if (uVar21 != 0) goto LAB_00170978;
    iVar38 = 0x46;
    *(char **)(puVar7 + 0x68) = pcVar27;
    *(int *)(puVar7 + 0xc) = iVar15;
    *(code **)(puVar7 + 0x138) = param_1;
    iVar12 = 0x77;
    param_7 = 0x28;
    puVar39 = (undefined8 *)0x8d;
LAB_0017039c:
    uVar26 = *(undefined8 *)(puVar7 + 200);
  }
  goto LAB_001703a0;
code_r0x00170990:
  *(undefined4 *)(puVar7 + 0x1cc) = 0x1a4;
  *(undefined4 *)(puVar7 + 0x1c8) = 0x3b;
  iVar38 = *(int *)(puVar7 + 0x1c8) * *(int *)(puVar7 + 0x1c8);
  pcVar33 = (code *)(ulong)(uint)(iVar38 * 8);
  uVar10 = iVar38 * 7;
  pcVar31 = (code *)(ulong)uVar10;
  uVar21 = 0x39;
  pcVar34 = *(code **)(puVar7 + 0x10);
  if (*(int *)(puVar7 + 0x1cc) * *(int *)(puVar7 + 0x1cc) + 1U != uVar10) {
LAB_00170a3c:
    param_1 = pcVar34;
    uVar11 = 0;
    puVar42 = (undefined8 *)0x95;
    puVar39 = (undefined8 *)0x7b;
    goto LAB_0017087c;
  }
  goto LAB_00170984;
joined_r0x0017120c:
  if (iVar12 == 0x8d) {
LAB_0017125c:
    if (uVar11 != 0) {
      *(undefined4 *)(puVar7 + 0x21c) = 0x11b;
      *(undefined4 *)(puVar7 + 0x218) = 0x12a;
      pcVar33 = (code *)(ulong)*(uint *)(puVar7 + 0x218);
      puVar39 = (undefined8 *)0x7b;
      if (*(int *)(puVar7 + 0x21c) * *(int *)(puVar7 + 0x21c) * -0x49249249 + 0xb6db6db7U <
          0x24924925 && (int)*(uint *)(puVar7 + 0x218) < 0x1cf) {
        uVar11 = 0;
      }
      iVar12 = 3;
      *(uint *)(puVar7 + 8) = uVar24;
      goto LAB_00170f8c;
    }
    uVar11 = 0x39;
    uVar25 = 1;
    if ((uVar24 & 1) == 0) goto LAB_001712e8;
  }
  else {
    if (uVar11 == 0) {
      puVar7 = puVar7 + 0xf02;
    }
    uVar11 = 0;
    cVar3 = *(char *)(*(long *)(puVar7 + 0xa8) + 2);
    *(undefined4 *)(puVar7 + 0x214) = 0;
    *(undefined4 *)(puVar7 + 0x210) = 0xb9;
    uVar24 = (uint)(cVar3 == 'w');
    iVar12 = *(int *)(puVar7 + 0x210) * *(int *)(puVar7 + 0x210);
    pcVar33 = (code *)(ulong)(uint)(iVar12 * 8);
    uVar25 = uVar24;
    if (*(int *)(puVar7 + 0x214) * *(int *)(puVar7 + 0x214) + 1 != iVar12 * 7) {
      puVar39 = (undefined8 *)0x8d;
      goto LAB_0017125c;
    }
  }
  iVar12 = (int)puVar39;
  uVar24 = uVar25;
  goto joined_r0x0017120c;
LAB_001712e8:
  *(undefined4 *)(puVar7 + 8) = 0;
  puVar39 = (undefined8 *)0x8d;
  iVar12 = 0x95;
LAB_00170f8c:
  iVar38 = (int)puVar39;
  param_4 = (code *)((ulong)param_4 & 0xffffffff);
  lVar22 = *(long *)(puVar7 + 0x138);
  *(uint *)(puVar7 + 0x1c) = uVar21;
  uVar21 = uVar18;
  uVar24 = uVar11;
  if (iVar12 == 3) {
    do {
      while (uVar18 = uVar21, (int)puVar39 != 0x8d) {
        if (uVar11 == 0) {
          puVar7 = puVar7 + 0x641;
        }
        cVar3 = *(char *)(*(long *)(puVar7 + 0xa8) + 3);
        *(undefined4 *)(puVar7 + 0x224) = 0x86;
        *(undefined4 *)(puVar7 + 0x220) = 0x4c;
        uVar21 = (uint)(cVar3 == -0x10);
        if ((0x18d < *(int *)(puVar7 + 0x220)) ||
           (uVar11 = 0, (*(int *)(puVar7 + 0x224) * *(int *)(puVar7 + 0x224) + 1U) % 7 != 0)) {
          uVar11 = 0;
          puVar39 = (undefined8 *)0x8d;
        }
      }
      pcVar33 = (code *)(ulong)uVar18;
      if (uVar11 == 0x39) {
        *(undefined4 *)(puVar7 + 0x22c) = 0x1ac;
        *(undefined4 *)(puVar7 + 0x228) = 0x1dd;
        uVar11 = 0x39;
        if (*(int *)(puVar7 + 0x22c) * *(int *)(puVar7 + 0x22c) * -0x5e50d794 + 0xa1af286cU <
            0xd79435f && *(int *)(puVar7 + 0x228) < 0x14f) {
          uVar11 = 0;
        }
        iVar38 = 0x7b;
        uVar24 = uVar11;
        goto LAB_001710a8;
      }
      uVar11 = 0x39;
      uVar21 = 1;
    } while ((uVar18 & 1) != 0);
    iVar38 = 0x8d;
    uVar11 = 0x39;
    uVar24 = uVar11;
  }
LAB_001710a8:
  do {
    if (iVar38 == 0x8d) goto LAB_00171110;
    if (uVar11 == 0) {
      puVar7 = puVar7 + 0xec0;
    }
    *(undefined4 *)(puVar7 + 0x234) = 0x4e;
    *(undefined4 *)(puVar7 + 0x230) = 0x1cb;
    uVar11 = 0;
    uVar21 = *(int *)(puVar7 + 0x234) * *(int *)(puVar7 + 0x234) * 4 + 4;
    param_1 = (code *)(ulong)(uVar21 - (int)((ulong)uVar21 * 0xaf286bcb >> 0x20));
    pcVar33 = (code *)(ulong)(uVar21 % 0x13);
  } while ((*(int *)(puVar7 + 0x230) < 0x15) && (uVar21 % 0x13 == 0));
  uVar24 = 0;
  lVar30 = lVar35 + lVar22;
LAB_00171110:
  *(uint *)(puVar7 + 0x20) = uVar18;
  *(long *)(puVar7 + 0x28) = lVar30;
  if (uVar24 == 0x39) {
    *(undefined4 *)(puVar7 + 0x23c) = 0xcd;
    *(undefined4 *)(puVar7 + 0x238) = 0x21;
    iVar12 = *(int *)(puVar7 + 0x23c);
    pcVar33 = (code *)(ulong)*(uint *)(puVar7 + 0x238);
    pcVar31 = (code *)0x39;
    puVar39 = (undefined8 *)0x7b;
    uVar11 = 0;
    if (0x329161f < (iVar12 + iVar12 * iVar12) * 0x781948b1 + 0x48b0fcd7U ||
        (int)*(uint *)(puVar7 + 0x238) < 0x140) {
      uVar11 = 0x39;
    }
  }
  else {
    pcVar31 = *(code **)(puVar7 + 0x28);
    uVar11 = 0x39;
    puVar39 = (undefined8 *)0x8d;
    *(code **)(puVar7 + 0x110) = pcVar31;
  }
  iVar38 = 0x73;
  puVar42 = (undefined8 *)0x3;
  uVar29 = 0xb9;
  iVar12 = 0x1f;
  param_7 = 0x89;
  *(char **)(puVar7 + 0x68) = pcVar27;
  uVar26 = *(undefined8 *)(puVar7 + 200);
  param_5 = (undefined8 **)(ulong)*(uint *)(puVar7 + 0xb4);
  *(uint *)(puVar7 + 0x18) = uVar10;
  param_3 = param_6;
  goto LAB_001703a0;
}

