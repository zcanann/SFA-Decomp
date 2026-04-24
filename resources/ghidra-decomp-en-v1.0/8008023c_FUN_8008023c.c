// Function: FUN_8008023c
// Entry: 8008023c
// Size: 260 bytes

undefined4 FUN_8008023c(int param_1)

{
  int iVar1;
  char cVar3;
  undefined4 uVar2;
  
  iVar1 = (int)(short)(&DAT_8039a3b0)[param_1];
  if ((DAT_803dd094 == 0) && (cVar3 = FUN_8000cfa0(), cVar3 == '\0')) {
    FLOAT_803dd074 =
         (float)(&DAT_8039a1ac)[param_1] -
         (float)((double)CONCAT44(0x43300000,DAT_803db728 ^ 0x80000000) - DOUBLE_803defb8);
    if (FLOAT_803defb0 != FLOAT_803dd074) {
      DAT_803db724 = param_1;
    }
    DAT_803db728 = 0xffffffff;
    if ((((iVar1 == 0x54c) || (iVar1 - 0x551U < 2)) || (iVar1 == 0x575)) ||
       ((iVar1 == 0x57a || (iVar1 == 0x57b)))) {
      FLOAT_803dd074 = FLOAT_803defb0;
      DAT_803db724 = -1;
    }
    DAT_803db720 = 0xffffffff;
    FUN_8000d138();
    uVar2 = 1;
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}

