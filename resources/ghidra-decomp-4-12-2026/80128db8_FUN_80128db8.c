// Function: FUN_80128db8
// Entry: 80128db8
// Size: 1012 bytes

/* WARNING: Removing unreachable block (ram,0x8012918c) */
/* WARNING: Removing unreachable block (ram,0x80129184) */
/* WARNING: Removing unreachable block (ram,0x8012917c) */
/* WARNING: Removing unreachable block (ram,0x80129174) */
/* WARNING: Removing unreachable block (ram,0x8012916c) */
/* WARNING: Removing unreachable block (ram,0x80129164) */
/* WARNING: Removing unreachable block (ram,0x8012915c) */
/* WARNING: Removing unreachable block (ram,0x80128df8) */
/* WARNING: Removing unreachable block (ram,0x80128df0) */
/* WARNING: Removing unreachable block (ram,0x80128de8) */
/* WARNING: Removing unreachable block (ram,0x80128de0) */
/* WARNING: Removing unreachable block (ram,0x80128dd8) */
/* WARNING: Removing unreachable block (ram,0x80128dd0) */
/* WARNING: Removing unreachable block (ram,0x80128dc8) */

void FUN_80128db8(undefined4 param_1,undefined4 param_2,byte param_3)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  short sVar6;
  ushort uVar7;
  int iVar5;
  short *psVar8;
  undefined uVar9;
  char cVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  double dVar15;
  double dVar16;
  double dVar17;
  double dVar18;
  undefined8 uVar19;
  undefined8 local_a8;
  
  uVar19 = FUN_80286824();
  iVar1 = (int)(((double)CONCAT44(0x43300000,(int)(short)uVar19 ^ 0x80000000) - DOUBLE_803e2af8) *
                (DOUBLE_803e2d00 -
                ((double)CONCAT44(0x43300000,(int)DAT_803de3dc ^ 0x80000000) - DOUBLE_803e2af8)) *
               DOUBLE_803e2d08);
  uVar2 = (uint)((ulonglong)uVar19 >> 0x20) & 0xff;
  iVar3 = uVar2 * 0x20;
  if (-1 < *(short *)(DAT_803de4a4 + iVar3)) {
    iVar4 = (int)(short)iVar1;
    iVar4 = iVar4 / 0xf + (iVar4 >> 0x1f);
    dVar17 = (double)FLOAT_803e2d44;
    dVar11 = DOUBLE_803e2d98;
    dVar12 = DOUBLE_803e2db8;
    dVar18 = DOUBLE_803e2b08;
    for (cVar10 = DAT_803de4a4[iVar3 + 10]; -1 < cVar10; cVar10 = cVar10 + -4) {
      psVar8 = (short *)(DAT_803de4a4 + iVar3);
      dVar15 = (double)(float)(dVar17 * (double)*(float *)(psVar8 + 8));
      local_a8 = (double)CONCAT44(0x43300000,(uint)(ushort)psVar8[1]);
      dVar14 = (double)(float)(local_a8 - dVar18);
      dVar13 = (double)(float)((double)CONCAT44(0x43300000,(uint)(ushort)psVar8[2]) - dVar18);
      sVar6 = psVar8[3] - (short)cVar10;
      if ((uVar2 == DAT_803de458) && (DAT_803de4a4 != &DAT_8031c468)) {
        local_a8 = (double)CONCAT44(0x43300000,(int)DAT_803de3dc ^ 0x80000000);
        dVar16 = (double)(float)(dVar15 * (DOUBLE_803e2be0 +
                                          (local_a8 - DOUBLE_803e2af8) / DOUBLE_803e2da8));
        dVar15 = (double)FUN_802945e0();
        dVar15 = (double)(float)(dVar16 + (double)(float)((double)FLOAT_803e2d48 * dVar15 +
                                                         (double)FLOAT_803e2d10));
        dVar14 = (double)(float)((double)((float)((double)FLOAT_803e2bb4 - dVar14) *
                                         (float)((double)CONCAT44(0x43300000,
                                                                  (int)DAT_803de3dc ^ 0x80000000U) -
                                                DOUBLE_803e2af8)) * DOUBLE_803e2d08 + dVar14);
        dVar13 = (double)(float)((double)((float)((double)FLOAT_803e2db0 - dVar13) *
                                         (float)((double)CONCAT44(0x43300000,
                                                                  (int)DAT_803de3dc ^ 0x80000000U) -
                                                DOUBLE_803e2af8)) * DOUBLE_803e2d08 + dVar13);
        uVar9 = (char)uVar19;
      }
      else {
        if ((*psVar8 == 0x4a) || (iVar5 = iVar1, *psVar8 == 0x4c)) {
          uVar7 = (ushort)(int)FLOAT_803de3c8 & 0x1f;
          if (((int)FLOAT_803de3c8 & 0x10U) != 0) {
            uVar7 = uVar7 ^ 0x1f;
          }
          iVar5 = (int)(short)(uVar7 * ((short)iVar4 - (short)(iVar4 >> 0x1f)));
        }
        sVar6 = sVar6 - DAT_803de3dc;
        uVar9 = (char)iVar5;
      }
      psVar8 = (short *)(DAT_803de4a4 + iVar3);
      local_a8 = (double)CONCAT44(0x43300000,(uint)*(byte *)(psVar8 + 4));
      dVar14 = (double)(float)-(dVar11 * (double)(float)(dVar15 * (double)(float)(local_a8 - dVar18)
                                                        ) * dVar12 - dVar14);
      dVar13 = (double)(float)-(dVar11 * (double)(float)(dVar15 * (double)(float)((double)CONCAT44(
                                                  0x43300000,(uint)*(byte *)((int)psVar8 + 9)) -
                                                  dVar18)) * dVar12 - dVar13);
      if (DAT_803de4a4 == &DAT_8031c9e0) {
        if ((&DAT_803a97a8)[*psVar8] == 0xbf0) {
          sVar6 = sVar6 + -0x14;
        }
        if ((&DAT_803a97f8)[*psVar8] != 0) {
          FUN_8011f088(dVar14,dVar13,(&DAT_803a97f8)[*psVar8],(int)sVar6,uVar9,(int)dVar15,param_3);
        }
      }
      else {
        iVar5 = (int)*psVar8;
        if (iVar5 != 0) {
          if (iVar5 == 0x25) {
            sVar6 = sVar6 + -0x14;
          }
          FUN_8011f088(dVar14,dVar13,(&DAT_803a9610)[iVar5],(int)sVar6,uVar9,(int)dVar15,param_3);
        }
      }
    }
  }
  FUN_80286870();
  return;
}

