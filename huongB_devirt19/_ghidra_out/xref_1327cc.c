
/* WARNING: Removing unreachable block (ram,0x00232988) */
/* WARNING: Removing unreachable block (ram,0x00232990) */
/* WARNING: Removing unreachable block (ram,0x002329cc) */
/* WARNING: Removing unreachable block (ram,0x002329b8) */
/* WARNING: Removing unreachable block (ram,0x002329d0) */
/* WARNING: Removing unreachable block (ram,0x00232a10) */
/* WARNING: Removing unreachable block (ram,0x00232a14) */
/* WARNING: Removing unreachable block (ram,0x002329c4) */
/* WARNING: Removing unreachable block (ram,0x002329b4) */
/* WARNING: Removing unreachable block (ram,0x00232a24) */
/* WARNING: Removing unreachable block (ram,0x00232a28) */
/* WARNING: Removing unreachable block (ram,0x00232b64) */
/* WARNING: Removing unreachable block (ram,0x00232b74) */
/* WARNING: Removing unreachable block (ram,0x00232a44) */
/* WARNING: Removing unreachable block (ram,0x00232bb0) */
/* WARNING: Removing unreachable block (ram,0x00232bec) */
/* WARNING: Removing unreachable block (ram,0x00232c44) */
/* WARNING: Removing unreachable block (ram,0x00232c54) */
/* WARNING: Removing unreachable block (ram,0x00232c58) */
/* WARNING: Removing unreachable block (ram,0x00232d60) */
/* WARNING: Removing unreachable block (ram,0x00232c60) */
/* WARNING: Removing unreachable block (ram,0x00232c9c) */
/* WARNING: Removing unreachable block (ram,0x00232ca0) */
/* WARNING: Removing unreachable block (ram,0x00232ca4) */
/* WARNING: Removing unreachable block (ram,0x00232be4) */
/* WARNING: Removing unreachable block (ram,0x00232cac) */
/* WARNING: Removing unreachable block (ram,0x00232cd4) */
/* WARNING: Removing unreachable block (ram,0x00232cec) */
/* WARNING: Removing unreachable block (ram,0x00232d00) */
/* WARNING: Removing unreachable block (ram,0x00232d08) */
/* WARNING: Removing unreachable block (ram,0x00232bf8) */
/* WARNING: Removing unreachable block (ram,0x00232c30) */
/* WARNING: Removing unreachable block (ram,0x00232c34) */
/* WARNING: Removing unreachable block (ram,0x00232c40) */
/* WARNING: Removing unreachable block (ram,0x00232d0c) */
/* WARNING: Removing unreachable block (ram,0x00232d1c) */
/* WARNING: Removing unreachable block (ram,0x00232d20) */
/* WARNING: Removing unreachable block (ram,0x00232d5c) */
/* WARNING: Removing unreachable block (ram,0x00232d70) */
/* WARNING: Removing unreachable block (ram,0x00232db4) */
/* WARNING: Removing unreachable block (ram,0x00232e14) */
/* WARNING: Removing unreachable block (ram,0x00232e34) */
/* WARNING: Removing unreachable block (ram,0x00232e38) */
/* WARNING: Removing unreachable block (ram,0x00232e44) */
/* WARNING: Removing unreachable block (ram,0x00232dbc) */
/* WARNING: Removing unreachable block (ram,0x00232dc4) */
/* WARNING: Removing unreachable block (ram,0x00232e00) */
/* WARNING: Removing unreachable block (ram,0x00232e10) */
/* WARNING: Removing unreachable block (ram,0x00232dc8) */
/* WARNING: Removing unreachable block (ram,0x00232de0) */
/* WARNING: Removing unreachable block (ram,0x00232dfc) */
/* WARNING: Removing unreachable block (ram,0x00232e48) */
/* WARNING: Removing unreachable block (ram,0x00232e5c) */
/* WARNING: Removing unreachable block (ram,0x00232e7c) */
/* WARNING: Removing unreachable block (ram,0x00232cf8) */

void FUN_002327cc(void)

{
  undefined1 *puVar1;
  int iVar2;
  int iVar3;
  code *UNRECOVERED_JUMPTABLE;
  undefined1 auStack_f0 [8];
  long local_e8;
  undefined8 local_68;
  
  puVar1 = auStack_f0;
  local_e8 = tpidr_el0;
  iVar2 = 0x81;
  local_68 = *(undefined8 *)(local_e8 + 0x28);
  do {
    iVar3 = 0x98;
    do {
      if (iVar2 == 0x5c) {
        FUN_00234998(0x10);
                    /* WARNING: Could not recover jumptable at 0x00232928. Too many branches */
                    /* WARNING: Treating indirect jump as call */
        (*UNRECOVERED_JUMPTABLE)();
        return;
      }
      if (iVar3 != 0x98) {
        puVar1 = puVar1 + 0xb82;
        break;
      }
      *(undefined4 *)(puVar1 + 0x1c) = 0x172;
      *(undefined4 *)(puVar1 + 0x18) = 0x7d;
      iVar3 = 0x8a;
    } while (*(int *)(puVar1 + 0x1c) * *(int *)(puVar1 + 0x1c) + 1 ==
             *(int *)(puVar1 + 0x18) * *(int *)(puVar1 + 0x18) * 7);
    iVar2 = 0x5c;
  } while( true );
}

