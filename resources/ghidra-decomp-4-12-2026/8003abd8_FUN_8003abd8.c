// Function: FUN_8003abd8
// Entry: 8003abd8
// Size: 308 bytes

void FUN_8003abd8(int param_1,uint *param_2,int param_3,int param_4,int param_5)

{
  short sVar1;
  uint uVar2;
  short sVar3;
  short sVar4;
  short sVar5;
  int iVar6;
  short *psVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  
  for (iVar6 = 0; iVar6 < param_3; iVar6 = iVar6 + 1) {
    psVar7 = (short *)0x0;
    iVar8 = *(int *)(param_1 + 0x50);
    if (iVar8 != 0) {
      iVar9 = 0;
      iVar10 = 0;
      for (uVar2 = (uint)*(byte *)(iVar8 + 0x5a); uVar2 != 0; uVar2 = uVar2 - 1) {
        if ((*(char *)(*(int *)(iVar8 + 0x10) + *(char *)(param_1 + 0xad) + iVar9 + 1) != -1) &&
           (*param_2 == (uint)*(byte *)(*(int *)(iVar8 + 0x10) + iVar9))) {
          psVar7 = (short *)(*(int *)(param_1 + 0x6c) + iVar10);
        }
        iVar9 = *(char *)(iVar8 + 0x55) + iVar9 + 1;
        iVar10 = iVar10 + 0x12;
      }
    }
    if (psVar7 != (short *)0x0) {
      sVar1 = *psVar7;
      sVar5 = (short)param_4;
      sVar3 = (short)param_5;
      sVar4 = sVar5;
      if ((param_4 <= sVar1) && (sVar4 = sVar1, param_5 < sVar1)) {
        sVar4 = sVar3;
      }
      *psVar7 = sVar4;
      sVar1 = psVar7[1];
      sVar4 = sVar5;
      if ((param_4 <= sVar1) && (sVar4 = sVar1, param_5 < sVar1)) {
        sVar4 = sVar3;
      }
      psVar7[1] = sVar4;
      sVar1 = psVar7[2];
      if ((param_4 <= sVar1) && (sVar5 = sVar1, param_5 < sVar1)) {
        sVar5 = sVar3;
      }
      psVar7[2] = sVar5;
    }
    param_2 = param_2 + 1;
  }
  return;
}

