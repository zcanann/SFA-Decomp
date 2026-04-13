// Function: FUN_80240ad0
// Entry: 80240ad0
// Size: 40 bytes

int FUN_80240ad0(void)

{
  int iVar1;
  
  if ((DAT_803dea58 == 0) || (iVar1 = *(int *)(DAT_803dea58 + 0x2c), iVar1 == 0)) {
    iVar1 = 0x10000002;
  }
  return iVar1;
}

