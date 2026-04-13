// Function: FUN_80089a60
// Entry: 80089a60
// Size: 88 bytes

void FUN_80089a60(int param_1,undefined4 *param_2,undefined4 *param_3,undefined4 *param_4)

{
  float fVar1;
  int iVar2;
  
  fVar1 = FLOAT_803dfcd8;
  if (DAT_803dddac == 0) {
    *param_2 = FLOAT_803dfcd8;
    *param_3 = FLOAT_803dfcec;
    *param_4 = fVar1;
    return;
  }
  iVar2 = param_1 * 0xa4;
  *param_2 = *(undefined4 *)(DAT_803dddac + iVar2 + 0x90);
  *param_3 = *(undefined4 *)(DAT_803dddac + iVar2 + 0x94);
  *param_4 = *(undefined4 *)(DAT_803dddac + iVar2 + 0x98);
  return;
}

