
void FUN_0020b010(long param_1)

{
  long lVar1;
  code *UNRECOVERED_JUMPTABLE;
  undefined8 local_48;
  undefined8 uStack_40;
  undefined8 local_38;
  
  lVar1 = tpidr_el0;
  local_38 = *(undefined8 *)(lVar1 + 0x28);
  local_48 = 0;
  uStack_40 = 0;
  FUN_0025b594(*(undefined8 *)(param_1 + 8),*(undefined4 *)(param_1 + 4),&local_48);
  FUN_002119c8(0x14);
                    /* WARNING: Could not recover jumptable at 0x0020b070. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*UNRECOVERED_JUMPTABLE)();
  return;
}

