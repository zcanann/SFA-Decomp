// Function: FUN_80009174
// Entry: 80009174
// Size: 176 bytes

void FUN_80009174(int param_1,int *param_2)

{
  undefined4 uVar1;
  
  if (param_1 < 0) {
    FUN_8007d858();
    FUN_802493c8(param_2);
    uVar1 = FUN_800238f8(0);
    FUN_800238c4((uint)param_2);
    FUN_800238f8(uVar1);
  }
  else {
    FUN_802493c8(param_2);
    uVar1 = FUN_800238f8(0);
    FUN_800238c4((uint)param_2);
    FUN_800238f8(uVar1);
    DAT_803dd478 = DAT_803dd478 & 0xfffffeff;
    DAT_803dd474 = DAT_803dd474 | 0x100;
  }
  return;
}

