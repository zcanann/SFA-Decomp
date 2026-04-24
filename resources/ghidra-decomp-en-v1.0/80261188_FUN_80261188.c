// Function: FUN_80261188
// Entry: 80261188
// Size: 644 bytes

int FUN_80261188(int param_1,uint *param_2)

{
  short **ppsVar1;
  uint uVar2;
  ushort *puVar3;
  short *psVar4;
  short *psVar5;
  ushort uVar6;
  short sVar7;
  short sVar8;
  uint uVar9;
  int iVar10;
  int iVar11;
  short *local_18;
  int local_14;
  
  uVar2 = 0;
  iVar10 = 0;
  uVar9 = 0;
  ppsVar1 = &local_18;
  do {
    psVar5 = (short *)(*(int *)(param_1 + 0x80) + (uVar2 + 3) * 0x2000);
    *ppsVar1 = psVar5;
    puVar3 = (ushort *)(psVar5 + 2);
    sVar8 = 0;
    sVar7 = 0;
    iVar11 = 0x1ff;
    do {
      sVar7 = sVar7 + *puVar3 + puVar3[1] + puVar3[2] + puVar3[3] + puVar3[4] + puVar3[5] +
              puVar3[6] + puVar3[7];
      sVar8 = sVar8 + ~*puVar3 + ~puVar3[1] + ~puVar3[2] + ~puVar3[3] + ~puVar3[4] + ~puVar3[5] +
              ~puVar3[6] + ~puVar3[7];
      puVar3 = puVar3 + 8;
      iVar11 = iVar11 + -1;
    } while (iVar11 != 0);
    iVar11 = 6;
    do {
      uVar6 = *puVar3;
      puVar3 = puVar3 + 1;
      sVar7 = sVar7 + uVar6;
      sVar8 = sVar8 + ~uVar6;
      iVar11 = iVar11 + -1;
    } while (iVar11 != 0);
    if (sVar7 == -1) {
      sVar7 = 0;
    }
    if (sVar8 == -1) {
      sVar8 = 0;
    }
    if ((*psVar5 == sVar7) && (psVar5[1] == sVar8)) {
      psVar4 = psVar5 + 5;
      sVar7 = 0;
      for (uVar6 = 5; uVar6 < *(ushort *)(param_1 + 0x10); uVar6 = uVar6 + 1) {
        if (*psVar4 == 0) {
          sVar7 = sVar7 + 1;
        }
        psVar4 = psVar4 + 1;
      }
      if (sVar7 != psVar5[3]) {
        *(undefined4 *)(param_1 + 0x88) = 0;
        iVar10 = iVar10 + 1;
        uVar9 = uVar2;
      }
    }
    else {
      *(undefined4 *)(param_1 + 0x88) = 0;
      iVar10 = iVar10 + 1;
      uVar9 = uVar2;
    }
    uVar2 = uVar2 + 1;
    ppsVar1 = ppsVar1 + 1;
  } while ((int)uVar2 < 2);
  if (iVar10 == 0) {
    if (*(short **)(param_1 + 0x88) == (short *)0x0) {
      uVar9 = (uint)(-1 < (int)local_18[2] - (int)*(short *)(local_14 + 4));
      *(short **)(param_1 + 0x88) = (&local_18)[uVar9];
      FUN_80003494((&local_18)[uVar9],(&local_18)[uVar9 ^ 1],0x2000);
    }
    else {
      uVar9 = (uint)(*(short **)(param_1 + 0x88) != local_18);
    }
  }
  if (param_2 != (uint *)0x0) {
    *param_2 = uVar9;
  }
  return iVar10;
}

