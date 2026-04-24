// Function: FUN_8003b0d0
// Entry: 8003b0d0
// Size: 344 bytes

void FUN_8003b0d0(short *param_1,int param_2,int param_3,uint param_4)

{
  uint uVar1;
  short sVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  
  iVar6 = 0;
  iVar3 = *(int *)(param_1 + 0x28);
  if (iVar3 != 0) {
    iVar4 = 0;
    iVar5 = 0;
    for (uVar1 = (uint)*(byte *)(iVar3 + 0x5a); uVar1 != 0; uVar1 = uVar1 - 1) {
      if ((*(char *)(*(int *)(iVar3 + 0x10) + *(char *)((int)param_1 + 0xad) + iVar4 + 1) != -1) &&
         (*(char *)(*(int *)(iVar3 + 0x10) + iVar4) == '\0')) {
        iVar6 = *(int *)(param_1 + 0x36) + iVar5;
      }
      iVar4 = *(char *)(iVar3 + 0x55) + iVar4 + 1;
      iVar5 = iVar5 + 0x12;
    }
  }
  if (iVar6 != 0) {
    sVar2 = FUN_800217c0((double)(*(float *)(param_1 + 6) - *(float *)(param_2 + 0xc)),
                         (double)(*(float *)(param_1 + 10) - *(float *)(param_2 + 0x14)));
    *(short *)(param_3 + 0x14) = sVar2 - *param_1;
    sVar2 = (short)(int)(FLOAT_803de9ec *
                        (float)((double)CONCAT44(0x43300000,param_4 ^ 0x80000000) - DOUBLE_803de9d0)
                        );
    if ((int)sVar2 < (int)*(short *)(param_3 + 0x14)) {
      *(short *)(param_3 + 0x14) = sVar2;
    }
    iVar3 = -(int)sVar2;
    if (*(short *)(param_3 + 0x14) < iVar3) {
      *(short *)(param_3 + 0x14) = (short)iVar3;
    }
    *(undefined2 *)(iVar6 + 2) = *(undefined2 *)(param_3 + 0x14);
  }
  return;
}

