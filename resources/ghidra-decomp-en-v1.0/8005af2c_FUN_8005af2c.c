// Function: FUN_8005af2c
// Entry: 8005af2c
// Size: 116 bytes

undefined4 FUN_8005af2c(int param_1,int param_2,int param_3)

{
  int iVar1;
  
  if ((((-1 < param_1) && (-1 < param_2)) && (param_1 < 0x10)) && (param_2 < 0x10)) {
    iVar1 = (int)*(char *)((&DAT_803822b4)[param_3] + param_1 + param_2 * 0x10);
    if ((-1 < iVar1) && (iVar1 < (int)(uint)DAT_803dce98)) {
      return *(undefined4 *)(DAT_803dce9c + iVar1 * 4);
    }
    return 0;
  }
  return 0;
}

