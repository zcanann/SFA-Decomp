// Function: FUN_8028e3f0
// Entry: 8028e3f0
// Size: 652 bytes

void FUN_8028e3f0(undefined *param_1,int param_2,int param_3)

{
  byte *pbVar1;
  byte *pbVar2;
  byte *pbVar3;
  byte *pbVar4;
  byte *pbVar5;
  byte *pbVar6;
  byte *pbVar7;
  byte *pbVar8;
  byte *pbVar9;
  byte *pbVar10;
  byte *pbVar11;
  byte *pbVar12;
  byte *pbVar13;
  byte *pbVar14;
  byte bVar15;
  byte bVar16;
  char cVar17;
  int iVar18;
  byte *pbVar19;
  byte *pbVar20;
  byte *pbVar21;
  uint uVar22;
  uint uVar23;
  int iVar24;
  uint uVar25;
  byte *pbVar26;
  int iVar27;
  byte abStack89 [77];
  
  uVar25 = 0;
  iVar27 = (uint)*(byte *)(param_2 + 4) + (*(byte *)(param_3 + 4) - 1);
  *param_1 = 0;
  pbVar21 = (byte *)((int)register0x00000004 + -0x58) + iVar27 + 1;
  pbVar20 = pbVar21;
  for (; 0 < iVar27; iVar27 = iVar27 + -1) {
    iVar18 = *(byte *)(param_3 + 4) - 1;
    iVar24 = (iVar27 - iVar18) + -1;
    if (iVar24 < 0) {
      iVar24 = 0;
      iVar18 = iVar27 + -1;
    }
    uVar22 = (uint)*(byte *)(param_2 + 4) - iVar24;
    pbVar26 = (byte *)(param_2 + iVar24 + 5);
    pbVar19 = (byte *)(param_3 + iVar18 + 5);
    uVar23 = iVar18 + 1U;
    if ((int)uVar22 < (int)(iVar18 + 1U)) {
      uVar23 = uVar22;
    }
    if (0 < (int)uVar23) {
      uVar22 = uVar23 >> 3;
      if (uVar22 != 0) {
        do {
          bVar15 = *pbVar26;
          bVar16 = *pbVar19;
          pbVar1 = pbVar26 + 1;
          pbVar2 = pbVar19 + -1;
          pbVar3 = pbVar26 + 2;
          pbVar4 = pbVar19 + -2;
          pbVar5 = pbVar26 + 3;
          pbVar6 = pbVar19 + -3;
          pbVar7 = pbVar26 + 4;
          pbVar8 = pbVar19 + -4;
          pbVar9 = pbVar26 + 5;
          pbVar10 = pbVar19 + -5;
          pbVar11 = pbVar26 + 6;
          pbVar12 = pbVar19 + -6;
          pbVar13 = pbVar26 + 7;
          pbVar14 = pbVar19 + -7;
          pbVar26 = pbVar26 + 8;
          pbVar19 = pbVar19 + -8;
          uVar25 = uVar25 + (uint)bVar15 * (uint)bVar16 + (uint)*pbVar1 * (uint)*pbVar2 +
                   (uint)*pbVar3 * (uint)*pbVar4 + (uint)*pbVar5 * (uint)*pbVar6 +
                   (uint)*pbVar7 * (uint)*pbVar8 + (uint)*pbVar9 * (uint)*pbVar10 +
                   (uint)*pbVar11 * (uint)*pbVar12 + (uint)*pbVar13 * (uint)*pbVar14;
          uVar22 = uVar22 - 1;
        } while (uVar22 != 0);
        uVar23 = uVar23 & 7;
        if (uVar23 == 0) goto LAB_8028e544;
      }
      do {
        bVar15 = *pbVar26;
        pbVar26 = pbVar26 + 1;
        bVar16 = *pbVar19;
        pbVar19 = pbVar19 + -1;
        uVar25 = uVar25 + (uint)bVar15 * (uint)bVar16;
        uVar23 = uVar23 - 1;
      } while (uVar23 != 0);
    }
LAB_8028e544:
    uVar23 = uVar25 / 10;
    cVar17 = (char)uVar25;
    uVar25 = uVar25 / 10;
    pbVar20 = pbVar20 + -1;
    *pbVar20 = cVar17 + (char)uVar23 * -10;
  }
  *(short *)(param_1 + 2) = *(short *)(param_2 + 2) + *(short *)(param_3 + 2);
  if (uVar25 != 0) {
    pbVar20 = pbVar20 + -1;
    *pbVar20 = (byte)uVar25;
    *(short *)(param_1 + 2) = *(short *)(param_1 + 2) + 1;
  }
  iVar27 = 0;
  for (; (iVar27 < 0x24 && (pbVar20 < pbVar21)); pbVar20 = pbVar20 + 1) {
    iVar18 = iVar27 + 5;
    iVar27 = iVar27 + 1;
    param_1[iVar18] = *pbVar20;
  }
  param_1[4] = (char)iVar27;
  if ((pbVar20 < pbVar21) && (4 < *pbVar20)) {
    if (*pbVar20 == 5) {
      pbVar19 = pbVar20 + 1;
      iVar27 = (int)pbVar21 - (int)pbVar19;
      if (pbVar19 < pbVar21) {
        do {
          if (*pbVar19 != 0) goto LAB_8028e610;
          pbVar19 = pbVar19 + 1;
          iVar27 = iVar27 + -1;
        } while (iVar27 != 0);
      }
      if ((pbVar20[-1] & 1) == 0) {
        return;
      }
    }
LAB_8028e610:
    for (pbVar20 = param_1 + 5 + ((byte)param_1[4] - 1); 8 < *pbVar20; pbVar20 = pbVar20 + -1) {
      if (pbVar20 == param_1 + 5) {
        *pbVar20 = 1;
        *(short *)(param_1 + 2) = *(short *)(param_1 + 2) + 1;
        return;
      }
      *pbVar20 = 0;
    }
    *pbVar20 = *pbVar20 + 1;
  }
  return;
}

