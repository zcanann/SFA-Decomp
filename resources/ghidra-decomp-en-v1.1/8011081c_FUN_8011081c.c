// Function: FUN_8011081c
// Entry: 8011081c
// Size: 300 bytes

void FUN_8011081c(int param_1,uint param_2,undefined4 *param_3)

{
  float fVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xa4);
  if (DAT_803de230 == (undefined4 *)0x0) {
    DAT_803de230 = (undefined4 *)FUN_80023d8c(0x10,0xf);
  }
  if (param_3 == (undefined4 *)0x0) {
    *DAT_803de230 = *(undefined4 *)(iVar2 + 0x18);
    DAT_803de230[1] = *(undefined4 *)(iVar2 + 0x1c);
    DAT_803de230[2] = *(undefined4 *)(iVar2 + 0x20);
    fVar1 = (float)((double)CONCAT44(0x43300000,param_2 ^ 0x80000000) - DOUBLE_803e27b8);
  }
  else {
    *DAT_803de230 = *param_3;
    DAT_803de230[1] = param_3[1];
    DAT_803de230[2] = param_3[2];
    fVar1 = (float)param_3[3];
  }
  DAT_803de230[3] = fVar1;
  FUN_80021884();
  FUN_80021884();
  return;
}

