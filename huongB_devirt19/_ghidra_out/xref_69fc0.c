
/* WARNING: Removing unreachable block (ram,0x0016a018) */
/* WARNING: Removing unreachable block (ram,0x0016a04c) */

void FUN_00169fc0(undefined8 param_1)

{
  long *plVar1;
  undefined1 *puVar2;
  undefined1 *puVar3;
  undefined4 *puVar4;
  undefined1 *puVar5;
  undefined8 *puVar6;
  undefined4 uVar7;
  int iVar8;
  undefined8 uVar9;
  long lVar10;
  undefined1 auStack_530 [16];
  undefined1 auStack_520 [16];
  undefined1 auStack_510 [16];
  undefined1 auStack_500 [16];
  undefined1 auStack_4f0 [16];
  undefined1 auStack_4e0 [16];
  undefined1 auStack_4d0 [16];
  undefined1 auStack_4c0 [16];
  undefined1 auStack_4b0 [32];
  undefined1 auStack_490 [48];
  undefined1 auStack_460 [16];
  long local_450 [2];
  undefined1 auStack_440 [16];
  undefined1 auStack_430 [16];
  undefined1 auStack_420 [16];
  undefined1 auStack_410 [16];
  undefined4 local_400 [4];
  undefined8 local_3f0 [2];
  undefined1 auStack_3e0 [48];
  undefined1 auStack_3b0 [16];
  undefined1 auStack_3a0 [16];
  undefined1 auStack_390 [16];
  undefined1 auStack_380 [16];
  undefined1 auStack_370 [16];
  undefined1 auStack_360 [32];
  undefined1 auStack_340 [16];
  undefined1 auStack_330 [48];
  long local_300;
  undefined8 local_2f0;
  undefined8 local_2e8;
  undefined1 *local_2e0;
  undefined1 *local_2d8;
  undefined1 *local_2d0;
  undefined1 *local_2c8;
  undefined1 *local_2c0;
  undefined1 *local_2b8;
  undefined1 *local_2b0;
  undefined1 *local_2a8;
  undefined1 *local_2a0;
  long *local_298;
  undefined1 *local_290;
  undefined1 *local_288;
  undefined4 *local_280;
  undefined1 *local_278;
  undefined1 *local_270;
  undefined1 *local_268;
  undefined1 *local_260;
  undefined1 *local_258;
  undefined8 *local_250;
  undefined8 local_248;
  undefined4 local_240;
  undefined4 local_23c;
  undefined8 local_70;
  
  local_300 = tpidr_el0;
  local_70 = *(undefined8 *)(local_300 + 0x28);
  local_23c = 0xdf;
  local_240 = 0x192;
  local_2e8 = DAT_002f02a8;
  local_250 = local_3f0;
  local_280 = local_400;
  local_278 = auStack_410;
  local_288 = auStack_420;
  local_290 = auStack_430;
  local_268 = auStack_440;
  local_298 = local_450;
  local_270 = auStack_460;
  local_258 = auStack_490;
  local_260 = auStack_4b0;
  local_2e0 = auStack_4c0;
  local_2a0 = auStack_4d0;
  local_2a8 = auStack_4e0;
  local_2b0 = auStack_4f0;
  local_2b8 = auStack_500;
  local_2c0 = auStack_510;
  local_2c8 = auStack_520;
  local_2d0 = auStack_530;
  local_2f0 = 0xffffffffff999830;
  local_248 = param_1;
  uVar9 = (*(code *)(DAT_002f0298 + -0x6667d0))();
  FUN_0024fc68(auStack_340,uVar9);
  local_2d8 = auStack_330;
  FUN_0022cf84(auStack_330,3,auStack_340,10000);
  FUN_0024fe34(auStack_340);
  if (((DAT_002f4020 & 1) == 0) && (iVar8 = __cxa_guard_acquire(&DAT_002f4020), iVar8 != 0)) {
    DAT_002f4014 = 0xfff0bdc1;
    DAT_002f4000 = 0;
    DAT_002f4008 = 0;
    DAT_002f3ff8 = &PTR_FUN_002d9c90;
    DAT_002f4010 = 0;
    DAT_002f4018 = DAT_002f4014;
    __cxa_guard_release(&DAT_002f4020);
  }
  FUN_00230bb8(&DAT_002f3ff8);
  uVar9 = local_248;
  FUN_0015f584(auStack_370,local_248);
  FUN_00160ec8(auStack_380,uVar9);
  FUN_00160f58(auStack_390,uVar9);
  FUN_001602d0(auStack_3a0,uVar9);
  FUN_0015f5cc(auStack_3b0,uVar9);
  FUN_0015f65c(uVar9);
  FUN_00165a74(uVar9);
  FUN_00208210(auStack_360,2,auStack_370,auStack_380,auStack_390,auStack_3a0);
  FUN_0024fe34(auStack_3b0);
  FUN_0024fe34(auStack_3a0);
  FUN_0024fe34(auStack_390);
  FUN_0024fe34(auStack_380);
  FUN_0024fe34(auStack_370);
  FUN_0023fe00(auStack_3e0);
  uVar7 = FUN_0015f65c(uVar9);
  puVar5 = local_278;
  puVar4 = local_280;
  *local_280 = uVar7;
  FUN_0015f5cc(puVar5,uVar9);
  puVar3 = local_288;
  FUN_0015f584(local_288,uVar9);
  puVar2 = local_290;
  FUN_0015f614(local_290,uVar9);
  puVar6 = local_250;
  FUN_00241538(local_250,auStack_3e0,puVar4,puVar5,puVar3);
  FUN_0024fe34(puVar2);
  FUN_0024fe34(puVar3);
  FUN_0024fe34(puVar5);
  plVar1 = local_298;
  FUN_00242454(local_298,auStack_3e0,*puVar6);
  FUN_00165a74(uVar9);
  FUN_00242660(local_268,auStack_3e0,1);
  lVar10 = *plVar1;
  *plVar1 = 0;
  if (lVar10 != 0) {
    FUN_0024fe34(lVar10);
    _ZdlPv(lVar10);
  }
  FUN_0024fa94(local_270);
  lVar10 = FUN_0016a438(0x16a3f4);
                    /* WARNING: Could not recover jumptable at 0x0016a434. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*(code *)(lVar10 + 0x38))();
  return;
}

