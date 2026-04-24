// Function: FUN_80243338
// Entry: 80243338
// Size: 772 bytes

byte * FUN_80243338(byte *param_1,int param_2,int param_3,uint param_4,uint *param_5)

{
  ushort uVar1;
  ushort uVar2;
  uint uVar3;
  bool bVar4;
  ushort uVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  bool bVar9;
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
  uVar5 = (ushort)bVar17;
  if (uVar5 != 0) {
    pbVar22 = param_1 + 1;
    if (1 < DAT_803dc548) {
      if (DAT_800000cc == 0) {
        uVar1 = read_volatile_2(DAT_cc00206e);
        DAT_803dc548 = (ushort)((uVar1 & 2) != 0);
      }
      else {
        DAT_803dc548 = 0;
      }
    }
    if (DAT_803dc548 == 1) {
      bVar4 = true;
      bVar9 = false;
      if ((0x80 < bVar17) && (bVar17 < 0xa0)) {
        bVar9 = true;
      }
      if (!bVar9) {
        bVar9 = false;
        if ((0xdf < bVar17) && (bVar17 < 0xfd)) {
          bVar9 = true;
        }
        if (!bVar9) {
          bVar4 = false;
        }
      }
      if ((bVar4) && (*pbVar22 != 0)) {
        uVar5 = CONCAT11(bVar17,*pbVar22);
        pbVar22 = param_1 + 2;
      }
    }
    param_1 = pbVar22;
    iVar20 = DAT_803dde28 + 0x2c;
    iVar6 = FUN_80242c10(uVar5);
    uVar3 = param_4 << 2 | param_4 >> 0x1e;
    iVar14 = iVar6 / DAT_803dde34;
    iVar7 = *(int *)(DAT_803dde28 + 0x14);
    uVar5 = *(ushort *)(DAT_803dde28 + 0x1a);
    uVar1 = *(ushort *)(DAT_803dde28 + 0x12);
    uVar2 = *(ushort *)(DAT_803dde28 + 0x10);
    iVar16 = iVar6 - iVar14 * DAT_803dde34;
    iVar13 = iVar16 / (int)(uint)uVar5;
    iVar19 = DAT_803dde28 + *(int *)(DAT_803dde28 + 0x24);
    for (uVar21 = 0; (int)uVar21 < (int)(uint)*(ushort *)(DAT_803dde28 + 0x12); uVar21 = uVar21 + 1)
    {
      uVar8 = iVar13 * (uint)uVar1 + uVar21;
      for (iVar15 = 0; iVar15 < (int)(uint)*(ushort *)(DAT_803dde28 + 0x10); iVar15 = iVar15 + 1) {
        uVar18 = (iVar16 - iVar13 * (uint)uVar5) * (uint)uVar2 + iVar15;
        uVar10 = param_3 + iVar15;
        uVar11 = uVar18 + (((int)uVar18 >> 3) + (uint)((int)uVar18 < 0 && (uVar18 & 7) != 0)) * -8;
        uVar12 = uVar10 + (((int)uVar10 >> 3) + (uint)((int)uVar10 < 0 && (uVar10 & 7) != 0)) * -8;
        pbVar22 = (byte *)(param_2 + (((int)uVar21 >> 3) +
                                     (uint)((int)uVar21 < 0 && (uVar21 & 7) != 0)) *
                                     (((int)uVar3 >> 3) +
                                     (uint)((int)uVar3 < 0 && (param_4 << 2 & 4) != 0)) * 0x20 +
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
                   *(byte *)(iVar20 + ((int)(uint)*(byte *)(iVar19 + ((uint)(iVar14 * iVar7) >> 1) +
                                                            (((int)(uint)*(ushort *)
                                                                          (DAT_803dde28 + 0x1e) >> 3
                                                             ) * 0x20 >> 1) *
                                                            (((int)uVar8 >> 3) +
                                                            (uint)((int)uVar8 < 0 &&
                                                                  (uVar8 & 7) != 0)) +
                                                            (((int)uVar18 >> 3) +
                                                            (uint)((int)uVar18 < 0 &&
                                                                  (uVar18 & 7) != 0)) * 0x10 +
                                                            (uVar8 + (((int)uVar8 >> 3) +
                                                                     (uint)((int)uVar8 < 0 &&
                                                                           (uVar8 & 7) != 0)) * -8)
                                                            * 2 + ((int)uVar11 >> 2) +
                                                                  (uint)((int)uVar11 < 0 &&
                                                                        (uVar11 & 3) != 0)) >>
                                       ((uVar18 + (((int)uVar18 >> 2) +
                                                  (uint)((int)uVar18 < 0 && (uVar18 & 3) != 0)) * -4
                                        ) * -2 + 6 & 0x3f) & 3U)) & bVar17;
      }
    }
    if (param_5 != (uint *)0x0) {
      *param_5 = (uint)*(byte *)(DAT_803dde30 + iVar6);
    }
  }
  return param_1;
}

