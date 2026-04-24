// Function: FUN_800323d0
// Entry: 800323d0
// Size: 64 bytes

void FUN_800323d0(void)

{
  int iVar1;
  short sVar2;
  
  sVar2 = 0;
  iVar1 = 0;
  do {
    if (*(int *)(DAT_803dcbdc + iVar1) != 0) {
      *(int *)(DAT_803dcbdc + iVar1) = *(int *)(DAT_803dcbdc + iVar1) + -1;
    }
    iVar1 = iVar1 + 0x3c;
    sVar2 = sVar2 + 1;
  } while (sVar2 < 0x32);
  FLOAT_803dcbe8 = FLOAT_803db414;
  return;
}

