// Function: FUN_8003ac14
// Entry: 8003ac14
// Size: 232 bytes

void FUN_8003ac14(int param_1,uint *param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  short *psVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  
  for (iVar2 = 0; iVar2 < param_3; iVar2 = iVar2 + 1) {
    psVar3 = (short *)0x0;
    iVar4 = *(int *)(param_1 + 0x50);
    if (iVar4 != 0) {
      iVar5 = 0;
      iVar6 = 0;
      for (uVar1 = (uint)*(byte *)(iVar4 + 0x5a); uVar1 != 0; uVar1 = uVar1 - 1) {
        if ((*(char *)(*(int *)(iVar4 + 0x10) + *(char *)(param_1 + 0xad) + iVar5 + 1) != -1) &&
           (*param_2 == (uint)*(byte *)(*(int *)(iVar4 + 0x10) + iVar5))) {
          psVar3 = (short *)(*(int *)(param_1 + 0x6c) + iVar6);
        }
        iVar5 = *(char *)(iVar4 + 0x55) + iVar5 + 1;
        iVar6 = iVar6 + 0x12;
      }
    }
    if (psVar3 != (short *)0x0) {
      psVar3[1] = (short)(psVar3[1] * 3 >> 2);
      *psVar3 = (short)(*psVar3 * 3 >> 2);
      psVar3[2] = (short)(psVar3[2] * 3 >> 2);
    }
    param_2 = param_2 + 1;
  }
  return;
}

