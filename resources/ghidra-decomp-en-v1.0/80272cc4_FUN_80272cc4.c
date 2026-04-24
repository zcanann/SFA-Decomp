// Function: FUN_80272cc4
// Entry: 80272cc4
// Size: 176 bytes

void FUN_80272cc4(uint param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  
  FUN_80284af4();
  (&DAT_803bd9c4)[param_1 & 0xff] = 0;
  (&DAT_803bda04)[param_1 & 0xff] = 0;
  (&DAT_803de254)[param_1 & 0xff] = 0xff;
  iVar1 = (param_1 & 0xff) * 2;
  (&DAT_803de244)[param_1 & 0xff] = 0xff;
  (&DAT_803bda25)[iVar1] = 0;
  (&DAT_803bda24)[iVar1] = 0;
  FUN_80283b60(param_1,param_2,param_3);
  FUN_80284abc();
  return;
}

