// Function: FUN_800324c8
// Entry: 800324c8
// Size: 64 bytes

void FUN_800324c8(void)

{
  int iVar1;
  short sVar2;
  
  sVar2 = 0;
  iVar1 = 0;
  do {
    if (*(int *)(DAT_803dd85c + iVar1) != 0) {
      *(int *)(DAT_803dd85c + iVar1) = *(int *)(DAT_803dd85c + iVar1) + -1;
    }
    iVar1 = iVar1 + 0x3c;
    sVar2 = sVar2 + 1;
  } while (sVar2 < 0x32);
  FLOAT_803dd868 = FLOAT_803dc074;
  return;
}

