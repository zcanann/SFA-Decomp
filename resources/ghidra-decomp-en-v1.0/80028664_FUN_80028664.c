// Function: FUN_80028664
// Entry: 80028664
// Size: 1264 bytes

void FUN_80028664(int param_1,int param_2,int param_3)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  short sVar5;
  uint uVar6;
  short sVar7;
  int iVar8;
  int iVar9;
  short *psVar10;
  int iVar11;
  int iVar12;
  
  if ((*(ushort *)(param_3 + 2) & 0x40) == 0) {
    iVar12 = (*(byte *)(param_3 + 0xf3) - 1 & 0xfffffff8) + 8;
    iVar11 = *(int *)(param_3 + 0x68) + (uint)*(ushort *)(param_2 + 0x44) * iVar12;
    iVar12 = *(int *)(param_3 + 0x68) + (uint)*(ushort *)(param_2 + 0x46) * iVar12;
  }
  else {
    iVar11 = *(int *)(param_2 + (uint)*(ushort *)(param_2 + 0x44) * 4 + 0x1c);
    iVar12 = *(int *)(param_2 + (uint)*(ushort *)(param_2 + 0x46) * 4 + 0x1c);
  }
  iVar2 = *(int *)(param_1 + 0x50);
  iVar3 = 0;
  iVar8 = 0;
  iVar1 = 0;
  for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(iVar2 + 0x5a); iVar4 = iVar4 + 1) {
    uVar6 = (uint)*(byte *)(*(int *)(iVar2 + 0x10) + iVar3 + *(char *)(param_1 + 0xad) + 1);
    if (uVar6 != 0xff) {
      psVar10 = (short *)(*(int *)(param_1 + 0x6c) + iVar1);
      sVar5 = (short)((int)*(char *)(iVar11 + uVar6) << 6);
      sVar7 = (short)((int)*(char *)(iVar12 + uVar6) << 6);
      if (*psVar10 != 0) {
        (&DAT_80340740)[iVar8] = sVar5;
        (&DAT_80340740)[iVar8 + 1] = sVar7;
        iVar9 = iVar8 + 3;
        (&DAT_80340740)[iVar8 + 2] = *psVar10;
        iVar8 = iVar8 + 4;
        (&DAT_80340740)[iVar9] = *psVar10;
      }
      if (psVar10[1] != 0) {
        (&DAT_80340740)[iVar8] = sVar5 + 2;
        (&DAT_80340740)[iVar8 + 1] = sVar7 + 2;
        iVar9 = iVar8 + 3;
        (&DAT_80340740)[iVar8 + 2] = psVar10[1];
        iVar8 = iVar8 + 4;
        (&DAT_80340740)[iVar9] = psVar10[1];
      }
      if (psVar10[2] != 0) {
        (&DAT_80340740)[iVar8] = sVar5 + 4;
        (&DAT_80340740)[iVar8 + 1] = sVar7 + 4;
        iVar9 = iVar8 + 3;
        (&DAT_80340740)[iVar8 + 2] = psVar10[2];
        iVar8 = iVar8 + 4;
        (&DAT_80340740)[iVar9] = psVar10[2];
      }
      if (psVar10[3] != 0) {
        (&DAT_80340740)[iVar8] = sVar5 + 0xc;
        (&DAT_80340740)[iVar8 + 1] = sVar7 + 0xc;
        iVar9 = iVar8 + 3;
        (&DAT_80340740)[iVar8 + 2] = psVar10[3];
        iVar8 = iVar8 + 4;
        (&DAT_80340740)[iVar9] = psVar10[3];
      }
      if (psVar10[4] != 0) {
        (&DAT_80340740)[iVar8] = sVar5 + 0xe;
        (&DAT_80340740)[iVar8 + 1] = sVar7 + 0xe;
        iVar9 = iVar8 + 3;
        (&DAT_80340740)[iVar8 + 2] = psVar10[4];
        iVar8 = iVar8 + 4;
        (&DAT_80340740)[iVar9] = psVar10[4];
      }
      if (psVar10[5] != 0) {
        (&DAT_80340740)[iVar8] = sVar5 + 0x10;
        (&DAT_80340740)[iVar8 + 1] = sVar7 + 0x10;
        iVar9 = iVar8 + 3;
        (&DAT_80340740)[iVar8 + 2] = psVar10[5];
        iVar8 = iVar8 + 4;
        (&DAT_80340740)[iVar9] = psVar10[5];
      }
      if (psVar10[6] != 0) {
        (&DAT_80340740)[iVar8] = sVar5 + 0x18;
        (&DAT_80340740)[iVar8 + 1] = sVar7 + 0x18;
        iVar9 = iVar8 + 3;
        (&DAT_80340740)[iVar8 + 2] = psVar10[6];
        iVar8 = iVar8 + 4;
        (&DAT_80340740)[iVar9] = psVar10[6];
      }
      if (psVar10[7] != 0) {
        (&DAT_80340740)[iVar8] = sVar5 + 0x1a;
        (&DAT_80340740)[iVar8 + 1] = sVar7 + 0x1a;
        iVar9 = iVar8 + 3;
        (&DAT_80340740)[iVar8 + 2] = psVar10[7];
        iVar8 = iVar8 + 4;
        (&DAT_80340740)[iVar9] = psVar10[7];
      }
      if (psVar10[8] != 0) {
        (&DAT_80340740)[iVar8] = sVar5 + 0x1c;
        (&DAT_80340740)[iVar8 + 1] = sVar7 + 0x1c;
        iVar9 = iVar8 + 3;
        (&DAT_80340740)[iVar8 + 2] = psVar10[8];
        iVar8 = iVar8 + 4;
        (&DAT_80340740)[iVar9] = psVar10[8];
      }
    }
    iVar3 = *(char *)(iVar2 + 0x55) + iVar3 + 1;
    iVar1 = iVar1 + 0x12;
  }
  (&DAT_80340740)[iVar8] = 0x1000;
  (&DAT_80340740)[iVar8 + 1] = 0x1000;
  return;
}

