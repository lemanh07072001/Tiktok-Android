
void FUN_0018913c(undefined8 param_1,undefined8 *param_2,undefined8 param_3)

{
  bool bVar1;
  ulong uVar2;
  long *plVar3;
  long lVar4;
  long *plVar5;
  long *plVar6;
  
  plVar5 = (long *)*param_2;
  plVar6 = (long *)*plVar5;
  while( true ) {
    if (plVar6 == plVar5 + 1) {
      FUN_0024fa94(param_1);
      return;
    }
    uVar2 = FUN_00250660(plVar6 + 4,param_3);
    if ((uVar2 & 1) != 0) break;
    plVar3 = (long *)plVar6[1];
    if ((long *)plVar6[1] == (long *)0x0) {
      plVar3 = plVar6 + 2;
      bVar1 = (long *)*(long *)*plVar3 != plVar6;
      plVar6 = (long *)*plVar3;
      if (bVar1) {
        do {
          lVar4 = *plVar3;
          plVar3 = (long *)(lVar4 + 0x10);
          plVar6 = (long *)*plVar3;
        } while (*plVar6 != lVar4);
      }
    }
    else {
      do {
        plVar6 = plVar3;
        plVar3 = (long *)*plVar6;
      } while ((long *)*plVar6 != (long *)0x0);
    }
  }
  FUN_0024fd5c(param_1,plVar6 + 6);
  return;
}

