// Function: FUN_80060bb0
// Entry: 80060bb0
// Size: 100 bytes

void FUN_80060bb0(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  iVar2 = 0;
  for (iVar3 = 0; iVar3 < (int)(uint)DAT_803dce98; iVar3 = iVar3 + 1) {
    iVar5 = *(int *)(DAT_803dce9c + iVar2);
    if (iVar5 != 0) {
      iVar1 = 0;
      for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(iVar5 + 0xa1); iVar4 = iVar4 + 1) {
        *(undefined *)(*(int *)(iVar5 + 0x68) + iVar1 + 0x12) = 0;
        iVar1 = iVar1 + 0x1c;
      }
    }
    iVar2 = iVar2 + 4;
  }
  return;
}

