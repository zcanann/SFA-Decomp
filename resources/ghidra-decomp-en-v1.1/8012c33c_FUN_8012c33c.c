// Function: FUN_8012c33c
// Entry: 8012c33c
// Size: 1368 bytes

/* WARNING: Removing unreachable block (ram,0x8012c874) */
/* WARNING: Removing unreachable block (ram,0x8012c86c) */
/* WARNING: Removing unreachable block (ram,0x8012c864) */
/* WARNING: Removing unreachable block (ram,0x8012c85c) */
/* WARNING: Removing unreachable block (ram,0x8012c854) */
/* WARNING: Removing unreachable block (ram,0x8012c84c) */
/* WARNING: Removing unreachable block (ram,0x8012c844) */
/* WARNING: Removing unreachable block (ram,0x8012c83c) */
/* WARNING: Removing unreachable block (ram,0x8012c384) */
/* WARNING: Removing unreachable block (ram,0x8012c37c) */
/* WARNING: Removing unreachable block (ram,0x8012c374) */
/* WARNING: Removing unreachable block (ram,0x8012c36c) */
/* WARNING: Removing unreachable block (ram,0x8012c364) */
/* WARNING: Removing unreachable block (ram,0x8012c35c) */
/* WARNING: Removing unreachable block (ram,0x8012c354) */
/* WARNING: Removing unreachable block (ram,0x8012c34c) */

void FUN_8012c33c(void)

{
  float fVar1;
  bool bVar2;
  short sVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  ushort uVar7;
  byte bVar8;
  byte bVar9;
  uint uVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  double dVar15;
  double dVar16;
  double dVar17;
  
  FUN_80286830();
  iVar4 = FUN_8002bac4();
  uVar10 = 5;
  FUN_80296328(iVar4);
  bVar9 = 5;
  bVar8 = 1;
  uVar5 = FUN_8012b9f8();
  if ((uVar5 & 0xff) == 0) {
    bVar8 = 4;
    uVar10 = 2;
  }
  if (iVar4 == 0) {
    bVar2 = true;
  }
  else {
    bVar2 = false;
    iVar6 = FUN_8005b128();
    if ((iVar6 != 0) || (iVar4 = FUN_80297a08(iVar4), iVar4 == 0)) {
      bVar2 = true;
    }
  }
  if (((DAT_803dc084 == '\0') || (uVar7 = FUN_800ea540(), uVar7 < 3)) || (!bVar2)) {
    uVar10 = uVar10 - 1;
    bVar9 = 4;
  }
  sVar3 = -(short)DAT_803dc6cc * (short)(0x10000 / (uVar10 & 0xff)) - DAT_803de402;
  if (0x8000 < sVar3) {
    sVar3 = sVar3 + 1;
  }
  if (sVar3 < -0x8000) {
    sVar3 = sVar3 + -1;
  }
  iVar4 = (int)sVar3 / 7 + ((int)sVar3 >> 0x1f);
  DAT_803de402 = DAT_803de402 + ((short)iVar4 - (short)(iVar4 >> 0x1f));
  DAT_803de40a = DAT_803de40a + (ushort)DAT_803dc070;
  *DAT_803de4e8 = (short)((int)DAT_803de40a << 9);
  dVar11 = (double)FUN_802945e0();
  DAT_803de4e8[2] = (short)(int)((double)FLOAT_803e2e08 * dVar11);
  dVar11 = (double)FUN_802945e0();
  *(float *)(DAT_803de4e8 + 8) = (float)(DOUBLE_803e2e10 * dVar11 + (double)FLOAT_803e2e0c);
  dVar11 = DOUBLE_803e2af8;
  *(float *)(DAT_803de4e8 + 8) =
       *(float *)(DAT_803de4e8 + 8) -
       (float)((double)CONCAT44(0x43300000,
                                (0x400 - DAT_803de40c) * (0x400 - DAT_803de40c) ^ 0x80000000) -
              DOUBLE_803e2af8) / FLOAT_803e2e18;
  *(undefined4 *)(iRam803de4ec + 0x10) = *(undefined4 *)(DAT_803de4e8 + 8);
  *(float *)(iRam803de4ec + 8) =
       FLOAT_803e2e1c *
       (float)((double)CONCAT44(0x43300000,(int)DAT_803de40c ^ 0x80000000) - dVar11) *
       FLOAT_803e2e20;
  FUN_8002fb40((double)FLOAT_803e2ad8,(double)FLOAT_803dc074);
  dVar14 = (double)FLOAT_803e2e20;
  dVar15 = (double)FLOAT_803e2ae4;
  dVar16 = (double)FLOAT_803e2cd0;
  dVar17 = (double)FLOAT_803e2c90;
  dVar11 = DOUBLE_803e2af8;
  for (; bVar8 <= bVar9; bVar8 = bVar8 + 1) {
    uVar5 = (uint)bVar8;
    if (0x90000000 < *(uint *)((&DAT_803aa070)[uVar5] + 0x4c)) {
      *(undefined4 *)((&DAT_803aa070)[uVar5] + 0x4c) = 0;
    }
    fVar1 = FLOAT_803e2e24;
    if ((uint)bVar8 == (int)DAT_803dc6cc) {
      fVar1 = FLOAT_803e2c40;
    }
    *(float *)((&DAT_803aa070)[uVar5] + 8) =
         (float)((double)((float)((double)CONCAT44(0x43300000,(int)DAT_803de404 ^ 0x80000000) -
                                 dVar11) * fVar1) * dVar14);
    *(undefined *)((&DAT_803aa070)[uVar5] + 0x37) = 0xff;
    FUN_8002fb40((double)*(float *)(&DAT_8031cbf8 + uVar5 * 4),(double)FLOAT_803dc074);
    dVar12 = (double)FUN_802945e0();
    *(float *)((&DAT_803aa070)[uVar5] + 0xc) =
         (float)((double)((float)((double)CONCAT44(0x43300000,(int)DAT_803de404 ^ 0x80000000) -
                                 dVar11) * (float)(dVar15 * dVar12)) * dVar14 +
                (double)*(float *)(DAT_803de4e8 + 6));
    dVar12 = (double)FUN_802945e0();
    dVar13 = (double)(float)(dVar16 * dVar12 +
                            (double)(float)((double)*(float *)(DAT_803de4e8 + 8) + dVar17));
    dVar12 = (double)FUN_80294964();
    *(float *)((&DAT_803aa070)[uVar5] + 0x10) =
         (float)((double)((float)((double)CONCAT44(0x43300000,(int)DAT_803de404 ^ 0x80000000) -
                                 dVar11) * (float)(dVar15 - dVar12)) * dVar14 + dVar13);
    dVar12 = (double)FUN_80294964();
    *(float *)((&DAT_803aa070)[uVar5] + 0x14) =
         (float)((double)((float)((double)CONCAT44(0x43300000,(int)DAT_803de404 ^ 0x80000000) -
                                 dVar11) * (float)(dVar15 * dVar12)) * dVar14 +
                (double)*(float *)(DAT_803de4e8 + 10));
  }
  FUN_8028687c();
  return;
}

