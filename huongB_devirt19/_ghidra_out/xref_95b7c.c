
undefined8 * FUN_00195b7c(void)

{
  int iVar1;
  
  if (((DAT_002f4020 & 1) == 0) && (iVar1 = __cxa_guard_acquire(&DAT_002f4020), iVar1 != 0)) {
    DAT_002f4014 = 0xfff0bdc1;
    DAT_002f4000 = 0;
    DAT_002f4008 = 0;
    DAT_002f3ff8 = &PTR_FUN_002d9c90;
    DAT_002f4010 = 0;
    DAT_002f4018 = DAT_002f4014;
    __cxa_guard_release(&DAT_002f4020);
  }
  return &DAT_002f3ff8;
}

