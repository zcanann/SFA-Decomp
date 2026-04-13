// Function: FUN_80243a30
// Entry: 80243a30
// Size: 772 bytes

byte * FUN_80243a30(byte *param_1,int param_2,int param_3,uint param_4,uint *param_5)

{
  ushort uVar1;
  ushort uVar2;
  ushort uVar3;
  bool bVar4;
  bool bVar5;
  uint uVar6;
  uint uVar7;
  int iVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  int iVar13;
  int iVar14;
  int iVar15;
  int iVar16;
  byte bVar17;
  uint uVar18;
  int iVar19;
  int iVar20;
  uint uVar21;
  byte *pbVar22;
  
  bVar17 = *param_1;
  uVar6 = (uint)bVar17;
  if (uVar6 != 0) {
    pbVar22 = param_1 + 1;
    if (1 < DAT_803dd1b0) {
      if (DAT_800000cc == 0) {
        uVar1 = DAT_cc00206e;
        DAT_803dd1b0 = (ushort)((uVar1 & 2) != 0);
      }
      else {
        DAT_803dd1b0 = 0;
      }
    }
    if (DAT_803dd1b0 == 1) {
      bVar5 = true;
      bVar4 = false;
      if ((0x80 < bVar17) && (bVar17 < 0xa0)) {
        bVar4 = true;
      }
      if (!bVar4) {
        bVar4 = false;
        if ((0xdf < bVar17) && (bVar17 < 0xfd)) {
          bVar4 = true;
        }
        if (!bVar4) {
          bVar5 = false;
        }
      }
      if ((bVar5) && (*pbVar22 != 0)) {
        uVar6 = (uint)CONCAT11(bVar17,*pbVar22);
        pbVar22 = param_1 + 2;
      }
    }
    param_1 = pbVar22;
    iVar20 = DAT_803deaa8 + 0x2c;
    uVar7 = FUN_80243308(uVar6);
    uVar6 = param_4 << 2 | param_4 >> 0x1e;
    iVar14 = (int)uVar7 / DAT_803deab4;
    iVar8 = *(int *)(DAT_803deaa8 + 0x14);
    uVar1 = *(ushort *)(DAT_803deaa8 + 0x1a);
    uVar2 = *(ushort *)(DAT_803deaa8 + 0x12);
    uVar3 = *(ushort *)(DAT_803deaa8 + 0x10);
    iVar16 = uVar7 - iVar14 * DAT_803deab4;
    iVar13 = iVar16 / (int)(uint)uVar1;
    iVar19 = DAT_803deaa8 + *(int *)(DAT_803deaa8 + 0x24);
    for (uVar21 = 0; (int)uVar21 < (int)(uint)*(ushort *)(DAT_803deaa8 + 0x12); uVar21 = uVar21 + 1)
    {
      uVar9 = iVar13 * (uint)uVar2 + uVar21;
      for (iVar15 = 0; iVar15 < (int)(uint)*(ushort *)(DAT_803deaa8 + 0x10); iVar15 = iVar15 + 1) {
        uVar18 = (iVar16 - iVar13 * (uint)uVar1) * (uint)uVar3 + iVar15;
        uVar10 = param_3 + iVar15;
        uVar11 = uVar18 + (((int)uVar18 >> 3) + (uint)((int)uVar18 < 0 && (uVar18 & 7) != 0)) * -8;
        uVar12 = uVar10 + (((int)uVar10 >> 3) + (uint)((int)uVar10 < 0 && (uVar10 & 7) != 0)) * -8;
        pbVar22 = (byte *)(param_2 + (((int)uVar21 >> 3) +
                                     (uint)((int)uVar21 < 0 && (uVar21 & 7) != 0)) *
                                     (((int)uVar6 >> 3) +
                                     (uint)((int)uVar6 < 0 && (param_4 << 2 & 4) != 0)) * 0x20 +
                           (((int)uVar10 >> 3) + (uint)((int)uVar10 < 0 && (uVar10 & 7) != 0)) *
                           0x20 + (uVar21 + (((int)uVar21 >> 3) +
                                            (uint)((int)uVar21 < 0 && (uVar21 & 7) != 0)) * -8) * 4
                          + ((int)uVar12 >> 1) + (uint)((int)uVar12 < 0 && (uVar12 & 1) != 0));
        if (uVar10 == (((int)uVar10 >> 1) + (uint)((int)uVar10 < 0 && (uVar10 & 1) != 0)) * 2) {
          bVar17 = 0xf0;
        }
        else {
          bVar17 = 0xf;
        }
        *pbVar22 = *pbVar22 |
                   *(byte *)(iVar20 + ((int)(uint)*(byte *)(iVar19 + ((uint)(iVar14 * iVar8) >> 1) +
                                                            (((int)(uint)*(ushort *)
                                                                          (DAT_803deaa8 + 0x1e) >> 3
                                                             ) * 0x20 >> 1) *
                                                            (((int)uVar9 >> 3) +
                                                            (uint)((int)uVar9 < 0 &&
                                                                  (uVar9 & 7) != 0)) +
                                                            (((int)uVar18 >> 3) +
                                                            (uint)((int)uVar18 < 0 &&
                                                                  (uVar18 & 7) != 0)) * 0x10 +
                                                            (uVar9 + (((int)uVar9 >> 3) +
                                                                     (uint)((int)uVar9 < 0 &&
                                                                           (uVar9 & 7) != 0)) * -8)
                                                            * 2 + ((int)uVar11 >> 2) +
                                                                  (uint)((int)uVar11 < 0 &&
                                                                        (uVar11 & 3) != 0)) >>
                                       ((uVar18 + (((int)uVar18 >> 2) +
                                                  (uint)((int)uVar18 < 0 && (uVar18 & 3) != 0)) * -4
                                        ) * -2 + 6 & 0x3f) & 3U)) & bVar17;
      }
    }
    if (param_5 != (uint *)0x0) {
      *param_5 = (uint)*(byte *)(DAT_803deab0 + uVar7);
    }
  }
  return param_1;
}

