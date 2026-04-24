// Function: FUN_8001ff3c
// Entry: 8001ff3c
// Size: 120 bytes

int FUN_8001ff3c(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar1 = FUN_8001ffb4();
  iVar2 = iVar1 + 1;
  if (iVar2 < 1 << (*(byte *)(DAT_803dcadc + param_1 * 4 + 2) & 0x1f) + 1) {
    FUN_800200e8(param_1,iVar2);
    iVar1 = iVar2;
  }
  return iVar1;
}

