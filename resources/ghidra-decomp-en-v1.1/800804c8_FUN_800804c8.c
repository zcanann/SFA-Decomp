// Function: FUN_800804c8
// Entry: 800804c8
// Size: 260 bytes

undefined4 FUN_800804c8(int param_1)

{
  int iVar1;
  char cVar3;
  undefined4 uVar2;
  
  iVar1 = (int)(short)(&DAT_8039b010)[param_1];
  if ((DAT_803ddd14 == 0) && (cVar3 = FUN_8000cfc0(), cVar3 == '\0')) {
    FLOAT_803ddcf4 =
         (float)(&DAT_8039ae0c)[param_1] -
         (float)((double)CONCAT44(0x43300000,DAT_803dc388 ^ 0x80000000) - DOUBLE_803dfc38);
    if (FLOAT_803dfc30 != FLOAT_803ddcf4) {
      DAT_803dc384 = param_1;
    }
    DAT_803dc388 = 0xffffffff;
    if ((((iVar1 == 0x54c) || (iVar1 - 0x551U < 2)) || (iVar1 == 0x575)) ||
       ((iVar1 == 0x57a || (iVar1 == 0x57b)))) {
      FLOAT_803ddcf4 = FLOAT_803dfc30;
      DAT_803dc384 = -1;
    }
    DAT_803dc380 = 0xffffffff;
    FUN_8000d158();
    uVar2 = 1;
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}

