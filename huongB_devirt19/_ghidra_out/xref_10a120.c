
/* WARNING: Removing unreachable block (ram,0x0020a598) */
/* WARNING: Removing unreachable block (ram,0x0020a4a0) */
/* WARNING: Removing unreachable block (ram,0x0020a254) */
/* WARNING: Removing unreachable block (ram,0x0020a264) */
/* WARNING: Removing unreachable block (ram,0x0020a320) */
/* WARNING: Removing unreachable block (ram,0x0020a348) */
/* WARNING: Removing unreachable block (ram,0x0020a364) */
/* WARNING: Removing unreachable block (ram,0x0020a370) */
/* WARNING: Removing unreachable block (ram,0x0020a378) */
/* WARNING: Removing unreachable block (ram,0x0020a444) */
/* WARNING: Removing unreachable block (ram,0x0020a380) */
/* WARNING: Removing unreachable block (ram,0x0020a3e0) */
/* WARNING: Removing unreachable block (ram,0x0020a3e4) */
/* WARNING: Removing unreachable block (ram,0x0020a658) */
/* WARNING: Removing unreachable block (ram,0x0020a3ec) */
/* WARNING: Removing unreachable block (ram,0x0020a690) */
/* WARNING: Removing unreachable block (ram,0x0020a420) */
/* WARNING: Removing unreachable block (ram,0x0020a43c) */
/* WARNING: Removing unreachable block (ram,0x0020a558) */
/* WARNING: Removing unreachable block (ram,0x0020a478) */
/* WARNING: Removing unreachable block (ram,0x0020a5a8) */
/* WARNING: Removing unreachable block (ram,0x0020a5ac) */
/* WARNING: Removing unreachable block (ram,0x0020a5b4) */
/* WARNING: Removing unreachable block (ram,0x0020a5f8) */
/* WARNING: Removing unreachable block (ram,0x0020a5bc) */
/* WARNING: Removing unreachable block (ram,0x0020a5c8) */
/* WARNING: Removing unreachable block (ram,0x0020a5d0) */
/* WARNING: Removing unreachable block (ram,0x0020a67c) */
/* WARNING: Removing unreachable block (ram,0x0020a604) */
/* WARNING: Removing unreachable block (ram,0x0020a608) */
/* WARNING: Removing unreachable block (ram,0x0020a5d8) */
/* WARNING: Removing unreachable block (ram,0x0020a5ec) */
/* WARNING: Removing unreachable block (ram,0x0020a58c) */
/* WARNING: Removing unreachable block (ram,0x0020a614) */
/* WARNING: Removing unreachable block (ram,0x0020a6d8) */
/* WARNING: Removing unreachable block (ram,0x0020a6e0) */
/* WARNING: Removing unreachable block (ram,0x0020a708) */
/* WARNING: Removing unreachable block (ram,0x0020a6ec) */
/* WARNING: Removing unreachable block (ram,0x0020a700) */
/* WARNING: Removing unreachable block (ram,0x0020a70c) */
/* WARNING: Removing unreachable block (ram,0x0020a714) */
/* WARNING: Removing unreachable block (ram,0x0020a61c) */
/* WARNING: Removing unreachable block (ram,0x0020a470) */
/* WARNING: Removing unreachable block (ram,0x0020a4a4) */
/* WARNING: Removing unreachable block (ram,0x0020a4b8) */
/* WARNING: Removing unreachable block (ram,0x0020a4c8) */
/* WARNING: Removing unreachable block (ram,0x0020a4d0) */
/* WARNING: Removing unreachable block (ram,0x0020a57c) */
/* WARNING: Removing unreachable block (ram,0x0020a4dc) */
/* WARNING: Removing unreachable block (ram,0x0020a4fc) */
/* WARNING: Removing unreachable block (ram,0x0020a500) */
/* WARNING: Removing unreachable block (ram,0x0020a6a0) */
/* WARNING: Removing unreachable block (ram,0x0020a6d4) */
/* WARNING: Removing unreachable block (ram,0x0020a718) */
/* WARNING: Removing unreachable block (ram,0x0020a724) */
/* WARNING: Removing unreachable block (ram,0x0020a794) */
/* WARNING: Removing unreachable block (ram,0x0020a7cc) */
/* WARNING: Removing unreachable block (ram,0x0020a7a8) */
/* WARNING: Removing unreachable block (ram,0x0020a508) */
/* WARNING: Removing unreachable block (ram,0x0020a530) */
/* WARNING: Removing unreachable block (ram,0x0020a644) */
/* WARNING: Removing unreachable block (ram,0x0020a2a8) */

undefined8 FUN_0020a120(void)

{
  undefined8 uVar1;
  code *extraout_x14;
  
  uVar1 = tpidr_el0;
  FUN_0020ada4(0x14);
  (*extraout_x14)();
                    /* WARNING: Could not recover jumptable at 0x0020a230. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  uVar1 = (*(code *)&LAB_000000c1)();
  return uVar1;
}

