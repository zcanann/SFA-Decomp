// Function: FUN_8003b500
// Entry: 8003b500
// Size: 224 bytes

void FUN_8003b500(int param_1,int param_2)

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
    FUN_80039df8((double)FLOAT_803de9a4,param_1,param_2);
    *(ushort *)(param_2 + 0x1a) = *(ushort *)(param_2 + 0x1a) & 0xff;
  }
  return;
}

