// Function: FUN_80089ba8
// Entry: 80089ba8
// Size: 84 bytes

void FUN_80089ba8(int param_1,undefined *param_2,undefined *param_3,undefined *param_4)

{
  int iVar1;
  
  if (DAT_803dddac == 0) {
    *param_4 = 0xff;
    *param_3 = 0xff;
    *param_2 = 0xff;
    return;
  }
  iVar1 = param_1 * 0xa4;
  *param_2 = *(undefined *)(DAT_803dddac + iVar1 + 0x88);
  *param_3 = *(undefined *)(DAT_803dddac + iVar1 + 0x89);
  *param_4 = *(undefined *)(DAT_803dddac + iVar1 + 0x8a);
  return;
}

