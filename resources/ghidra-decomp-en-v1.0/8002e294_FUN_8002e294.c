// Function: FUN_8002e294
// Entry: 8002e294
// Size: 360 bytes

void FUN_8002e294(void)

{
  int iVar1;
  int iVar2;
  
  iVar1 = 0;
  for (iVar2 = 0; iVar2 < DAT_803dcb94; iVar2 = iVar2 + 1) {
    if (*(int *)(DAT_803dcb98 + iVar1) != 0) {
      FUN_8002be88(*(int *)(DAT_803dcb98 + iVar1),0);
      *(undefined4 *)(DAT_803dcb98 + iVar1) = 0;
    }
    iVar1 = iVar1 + 4;
  }
  DAT_803dcb94 = 0;
  DAT_803db448 = 0;
  iVar2 = DAT_803dcb84 + -1;
  iVar1 = iVar2 * 4;
  for (; -1 < iVar2; iVar2 = iVar2 + -1) {
    FUN_8002cbc4(*(undefined4 *)(DAT_803dcb88 + iVar1));
    iVar1 = iVar1 + -4;
  }
  iVar1 = 0;
  for (iVar2 = 0; iVar2 < DAT_803dcb94; iVar2 = iVar2 + 1) {
    if (*(int *)(DAT_803dcb98 + iVar1) != 0) {
      FUN_8002be88(*(int *)(DAT_803dcb98 + iVar1),0);
      *(undefined4 *)(DAT_803dcb98 + iVar1) = 0;
    }
    iVar1 = iVar1 + 4;
  }
  DAT_803db448 = 2;
  DAT_803dcb94 = 0;
  DAT_803dcb8c = 0;
  DAT_803dcb84 = 0;
  FUN_80013b6c(&DAT_803dcb7c,0x38);
  DAT_803dcb94 = 0;
  DAT_803dcb8c = 0;
  DAT_803dcb70 = 0;
  DAT_803dcb84 = 0;
  FUN_80013b6c(&DAT_803dcb7c,0x38);
  DAT_803dcbc4 = 0;
  FUN_8003744c();
  FUN_800369f0();
  (**(code **)(*DAT_803dca50 + 0x28))(0,0);
  FUN_8000ce54();
  return;
}

