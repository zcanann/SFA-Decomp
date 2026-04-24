// Function: FUN_800395d8
// Entry: 800395d8
// Size: 124 bytes

int FUN_800395d8(int param_1,uint param_2)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  iVar5 = 0;
  iVar4 = *(int *)(param_1 + 0x50);
  if (iVar4 != 0) {
    iVar3 = 0;
    iVar2 = 0;
    for (uVar1 = (uint)*(byte *)(iVar4 + 0x5a); uVar1 != 0; uVar1 = uVar1 - 1) {
      if ((*(char *)(*(int *)(iVar4 + 0x10) + *(char *)(param_1 + 0xad) + iVar3 + 1) != -1) &&
         (param_2 == *(byte *)(*(int *)(iVar4 + 0x10) + iVar3))) {
        iVar5 = *(int *)(param_1 + 0x6c) + iVar2;
      }
      iVar3 = *(char *)(iVar4 + 0x55) + iVar3 + 1;
      iVar2 = iVar2 + 0x12;
    }
  }
  return iVar5;
}

