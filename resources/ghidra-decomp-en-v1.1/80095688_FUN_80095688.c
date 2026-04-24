// Function: FUN_80095688
// Entry: 80095688
// Size: 760 bytes

/* WARNING: Removing unreachable block (ram,0x80095960) */
/* WARNING: Removing unreachable block (ram,0x80095958) */
/* WARNING: Removing unreachable block (ram,0x80095950) */
/* WARNING: Removing unreachable block (ram,0x80095948) */
/* WARNING: Removing unreachable block (ram,0x80095940) */
/* WARNING: Removing unreachable block (ram,0x800956b8) */
/* WARNING: Removing unreachable block (ram,0x800956b0) */
/* WARNING: Removing unreachable block (ram,0x800956a8) */
/* WARNING: Removing unreachable block (ram,0x800956a0) */
/* WARNING: Removing unreachable block (ram,0x80095698) */

void FUN_80095688(void)

{
  uint uVar1;
  undefined4 uVar2;
  char cVar3;
  char cVar4;
  short sVar5;
  ushort uVar6;
  uint uVar7;
  uint uVar8;
  float *pfVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  double dVar13;
  double dVar14;
  double dVar15;
  double dVar16;
  double dVar17;
  
  FUN_8028682c();
  FUN_8025898c(1,0);
  DAT_803dde80 = FUN_80023d8c(0xc0,0);
  DAT_803dde7c = FUN_80023d8c(0x400,0);
  uVar8 = 0;
  iVar10 = 0;
  dVar16 = (double)FLOAT_803dff94;
  dVar17 = (double)FLOAT_803dff78;
  dVar15 = DOUBLE_803dff88;
  do {
    uVar7 = 0;
    iVar11 = 0;
    iVar12 = iVar10 << 3;
    do {
      if (uVar8 == 0) {
        pfVar9 = (float *)(DAT_803dde80 + iVar11);
        dVar13 = (double)FUN_80294a4c();
        dVar14 = (double)FUN_802946dc();
        *pfVar9 = (float)dVar13;
        pfVar9[1] = FLOAT_803dff80;
        pfVar9[2] = (float)dVar14;
      }
      pfVar9 = (float *)(DAT_803dde7c + iVar12);
      *pfVar9 = (float)((double)(float)((double)CONCAT44(0x43300000,uVar7 ^ 0x80000000) - dVar15) /
                       dVar16);
      pfVar9[1] = (float)((double)(float)((double)CONCAT44(0x43300000,uVar8 ^ 0x80000000) - dVar15)
                         / dVar17);
      iVar11 = iVar11 + 0xc;
      iVar12 = iVar12 + 8;
      uVar7 = uVar7 + 1;
    } while ((int)uVar7 < 0x10);
    iVar10 = iVar10 + 0x10;
    uVar8 = uVar8 + 1;
  } while ((int)uVar8 < 8);
  FUN_80242114(DAT_803dde80,0xc0);
  FUN_80242114(DAT_803dde7c,0x400);
  DAT_803dde88 = FUN_80023d8c(0xb40,0x7f7f7fff);
  FUN_802420b0(DAT_803dde88,0xb40);
  FUN_8025d4a0(DAT_803dde88,0xb40);
  FUN_80258a60();
  uVar8 = 0;
  do {
    FUN_80259000(0x98,2,0x10);
    sVar5 = 7;
    cVar3 = '\x15';
    iVar12 = uVar8 + 0x70;
    iVar10 = (int)(uVar8 + 1) >> 0x1f;
    uVar1 = (iVar10 * 0x10 | (uVar8 + 1) * 0x10000000 + iVar10 >> 0x1c) - iVar10;
    iVar10 = uVar1 + 0x70;
    uVar7 = uVar8 & 0xffff;
    iVar11 = 4;
    do {
      DAT_cc008000._0_1_ = cVar3;
      DAT_cc008000._0_1_ = cVar3;
      DAT_cc008000._0_2_ = (short)uVar8;
      DAT_cc008000._0_2_ = sVar5;
      DAT_cc008000._0_2_ = (short)iVar12;
      DAT_cc008000._0_1_ = cVar3;
      DAT_cc008000._0_1_ = cVar3;
      DAT_cc008000._0_2_ = (short)uVar1;
      DAT_cc008000._0_2_ = sVar5;
      DAT_cc008000._0_2_ = (short)iVar10;
      cVar4 = cVar3 + -3;
      uVar6 = sVar5 - 1;
      DAT_cc008000._0_1_ = cVar4;
      DAT_cc008000._0_1_ = cVar4;
      DAT_cc008000._0_2_ = (short)uVar8;
      DAT_cc008000._0_2_ = uVar6;
      DAT_cc008000._0_2_ = (short)iVar12 + -0x10;
      DAT_cc008000._0_1_ = cVar4;
      DAT_cc008000._0_1_ = cVar4;
      DAT_cc008000._0_2_ = (short)uVar1;
      DAT_cc008000._0_2_ = uVar6;
      DAT_cc008000._0_2_ = (short)iVar10 + -0x10;
      cVar3 = cVar3 + -6;
      iVar12 = iVar12 + -0x20;
      iVar10 = iVar10 + -0x20;
      sVar5 = sVar5 + -2;
      iVar11 = iVar11 + -1;
    } while (iVar11 != 0);
    uVar8 = uVar8 + 1;
  } while ((int)uVar8 < 0xf);
  uVar2 = FUN_8025d568(uVar1 & 0xffff,(uint)uVar6,uVar7);
  DAT_803dde84 = (undefined2)uVar2;
  FUN_8025898c(1,8);
  FUN_80286878();
  return;
}

