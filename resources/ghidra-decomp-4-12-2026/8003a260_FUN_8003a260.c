// Function: FUN_8003a260
// Entry: 8003a260
// Size: 200 bytes

void FUN_8003a260(int param_1,int param_2)

{
  uint uVar1;
  short *psVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  psVar2 = (short *)0x0;
  iVar3 = *(int *)(param_1 + 0x50);
  if (iVar3 != 0) {
    iVar4 = 0;
    iVar5 = 0;
    for (uVar1 = (uint)*(byte *)(iVar3 + 0x5a); uVar1 != 0; uVar1 = uVar1 - 1) {
      if ((*(char *)(*(int *)(iVar3 + 0x10) + *(char *)(param_1 + 0xad) + iVar4 + 1) != -1) &&
         (*(char *)(*(int *)(iVar3 + 0x10) + iVar4) == '\0')) {
        psVar2 = (short *)(*(int *)(param_1 + 0x6c) + iVar5);
      }
      iVar4 = *(char *)(iVar3 + 0x55) + iVar4 + 1;
      iVar5 = iVar5 + 0x12;
    }
  }
  if (psVar2 != (short *)0x0) {
    if (*psVar2 != 0) {
      uVar1 = *psVar2 * 3;
      *psVar2 = (short)((int)uVar1 >> 2) + (ushort)((int)uVar1 < 0 && (uVar1 & 3) != 0);
    }
    if (psVar2[1] != 0) {
      uVar1 = psVar2[1] * 3;
      psVar2[1] = (short)((int)uVar1 >> 2) + (ushort)((int)uVar1 < 0 && (uVar1 & 3) != 0);
    }
    *(undefined2 *)(param_2 + 0x1a) = 0;
    return;
  }
  return;
}

