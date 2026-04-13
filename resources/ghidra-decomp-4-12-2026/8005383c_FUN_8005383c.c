// Function: FUN_8005383c
// Entry: 8005383c
// Size: 64 bytes

uint FUN_8005383c(uint param_1)

{
  int iVar1;
  
  if ((param_1 & 0x80000000) != 0) {
    return param_1;
  }
  iVar1 = param_1 - 1;
  if ((-1 < iVar1) && (iVar1 < DAT_803dda3c)) {
    return *(uint *)(DAT_803dda44 + iVar1 * 0x10 + 4);
  }
  return 0;
}

