// Function: FUN_80089ab8
// Entry: 80089ab8
// Size: 156 bytes

void FUN_80089ab8(int param_1,byte *param_2,byte *param_3,byte *param_4)

{
  int iVar1;
  
  if (DAT_803dddac == 0) {
    *param_4 = 0xff;
    *param_3 = 0xff;
    *param_2 = 0xff;
  }
  else {
    iVar1 = param_1 * 0xa4;
    *param_2 = *(byte *)(DAT_803dddac + iVar1 + 0x78);
    *param_3 = *(byte *)(DAT_803dddac + iVar1 + 0x79);
    *param_4 = *(byte *)(DAT_803dddac + iVar1 + 0x7a);
  }
  *param_2 = (byte)((uint)*param_2 * (uint)DAT_803dc294 >> 8);
  *param_3 = (byte)((uint)*param_3 * (uint)DAT_803dc294 >> 8);
  *param_4 = (byte)((uint)*param_4 * (uint)DAT_803dc294 >> 8);
  return;
}

