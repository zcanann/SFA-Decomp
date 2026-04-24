// Function: FUN_800536c0
// Entry: 800536c0
// Size: 64 bytes

uint FUN_800536c0(uint param_1)

{
  int iVar1;
  
  if ((param_1 & 0x80000000) != 0) {
    return param_1;
  }
  iVar1 = param_1 - 1;
  if ((-1 < iVar1) && (iVar1 < DAT_803dcdbc)) {
    return *(uint *)(DAT_803dcdc4 + iVar1 * 0x10 + 4);
  }
  return 0;
}

