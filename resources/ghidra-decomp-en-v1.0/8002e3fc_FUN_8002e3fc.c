// Function: FUN_8002e3fc
// Entry: 8002e3fc
// Size: 128 bytes

void FUN_8002e3fc(void)

{
  int iVar1;
  int iVar2;
  
  iVar2 = 0;
  for (iVar1 = 0; iVar1 < DAT_803dcb94; iVar1 = iVar1 + 1) {
    if (*(int *)(DAT_803dcb98 + iVar2) != 0) {
      FUN_8002be88(*(int *)(DAT_803dcb98 + iVar2),0);
      *(undefined4 *)(DAT_803dcb98 + iVar2) = 0;
    }
    iVar2 = iVar2 + 4;
  }
  DAT_803dcb94 = 0;
  return;
}

