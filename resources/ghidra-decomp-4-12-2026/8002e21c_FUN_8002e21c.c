// Function: FUN_8002e21c
// Entry: 8002e21c
// Size: 108 bytes

void FUN_8002e21c(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  iVar2 = 0;
  for (iVar3 = 0; iVar3 < DAT_803dd804; iVar3 = iVar3 + 1) {
    iVar4 = *(int *)(DAT_803dd808 + iVar2);
    *(byte *)(iVar4 + 0xaf) = *(byte *)(iVar4 + 0xaf) & 0xf8;
    if (*(int *)(iVar4 + 0xc0) != 0) {
      if ((*(int *)(iVar4 + 0x30) == 0) &&
         (iVar1 = *(int *)(*(int *)(iVar4 + 0xc0) + 0x30), iVar1 != 0)) {
        *(int *)(iVar4 + 0x30) = iVar1;
      }
      *(undefined4 *)(iVar4 + 0xc0) = 0;
    }
    iVar2 = iVar2 + 4;
  }
  return;
}

