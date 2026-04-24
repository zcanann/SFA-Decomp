// Function: FUN_80063368
// Entry: 80063368
// Size: 64 bytes

void FUN_80063368(int param_1)

{
  int iVar1;
  short sVar2;
  
  iVar1 = 0;
  for (sVar2 = 0; sVar2 < 0x40; sVar2 = sVar2 + 1) {
    if (*(int *)(DAT_803dcf48 + iVar1) == param_1) {
      *(undefined *)((int *)(DAT_803dcf48 + iVar1) + 5) = 0;
    }
    iVar1 = iVar1 + 0x18;
  }
  return;
}

