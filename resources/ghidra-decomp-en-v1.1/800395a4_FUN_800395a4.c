// Function: FUN_800395a4
// Entry: 800395a4
// Size: 100 bytes

int FUN_800395a4(int param_1,uint param_2)

{
  uint uVar1;
  int iVar2;
  byte *pbVar3;
  int iVar4;
  int iVar5;
  
  iVar5 = 0;
  iVar2 = *(int *)(param_1 + 0x50);
  if (iVar2 != 0) {
    pbVar3 = *(byte **)(iVar2 + 0xc);
    if (pbVar3 == (byte *)0x0) {
      return 0;
    }
    iVar4 = 0;
    for (uVar1 = (uint)*(byte *)(iVar2 + 0x59); uVar1 != 0; uVar1 = uVar1 - 1) {
      if (param_2 == *pbVar3) {
        iVar5 = *(int *)(param_1 + 0x70) + iVar4;
      }
      pbVar3 = pbVar3 + 2;
      iVar4 = iVar4 + 0x10;
    }
  }
  return iVar5;
}

