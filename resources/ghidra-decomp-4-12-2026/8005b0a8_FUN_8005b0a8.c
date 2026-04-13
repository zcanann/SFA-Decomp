// Function: FUN_8005b0a8
// Entry: 8005b0a8
// Size: 116 bytes

undefined4 FUN_8005b0a8(int param_1,int param_2,int param_3)

{
  int iVar1;
  
  if ((((-1 < param_1) && (-1 < param_2)) && (param_1 < 0x10)) && (param_2 < 0x10)) {
    iVar1 = (int)*(char *)((&DAT_80382f14)[param_3] + param_1 + param_2 * 0x10);
    if ((-1 < iVar1) && (iVar1 < (int)(uint)DAT_803ddb18)) {
      return *(undefined4 *)(DAT_803ddb1c + iVar1 * 4);
    }
    return 0;
  }
  return 0;
}

