// Function: FUN_800953fc
// Entry: 800953fc
// Size: 760 bytes

/* WARNING: Removing unreachable block (ram,0x800956cc) */
/* WARNING: Removing unreachable block (ram,0x800956bc) */
/* WARNING: Removing unreachable block (ram,0x800956b4) */
/* WARNING: Removing unreachable block (ram,0x800956c4) */
/* WARNING: Removing unreachable block (ram,0x800956d4) */

void FUN_800953fc(void)

{
  undefined2 uVar1;
  char cVar2;
  char cVar3;
  int iVar4;
  short sVar5;
  uint uVar6;
  uint uVar7;
  float *pfVar8;
  int iVar9;
  uint uVar10;
  int iVar11;
  int iVar12;
  undefined4 uVar13;
  double dVar14;
  undefined8 in_f27;
  double dVar15;
  undefined8 in_f28;
  undefined8 in_f29;
  double dVar16;
  undefined8 in_f30;
  double dVar17;
  undefined8 in_f31;
  double dVar18;
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar13 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  __psq_st0(auStack72,(int)((ulonglong)in_f27 >> 0x20),0);
  __psq_st1(auStack72,(int)in_f27,0);
  FUN_802860c8();
  FUN_80258228(1,0);
  DAT_803dd200 = FUN_80023cc8(0xc0,0,0);
  DAT_803dd1fc = FUN_80023cc8(0x400,0,0);
  uVar7 = 0;
  iVar9 = 0;
  dVar17 = (double)FLOAT_803df314;
  dVar18 = (double)FLOAT_803df2f8;
  dVar16 = DOUBLE_803df308;
  do {
    uVar6 = 0;
    iVar11 = 0;
    uVar10 = 0;
    iVar12 = iVar9 << 3;
    do {
      if (uVar7 == 0) {
        pfVar8 = (float *)(DAT_803dd200 + iVar11);
        dVar15 = (double)((FLOAT_803df310 *
                          (float)((double)CONCAT44(0x43300000,uVar10 ^ 0x80000000) - DOUBLE_803df308
                                 )) / FLOAT_803df314);
        dVar14 = (double)FUN_802942ec(dVar15);
        dVar15 = (double)FUN_80293f7c(dVar15);
        *pfVar8 = (float)dVar14;
        pfVar8[1] = FLOAT_803df300;
        pfVar8[2] = (float)dVar15;
      }
      pfVar8 = (float *)(DAT_803dd1fc + iVar12);
      *pfVar8 = (float)((double)(float)((double)CONCAT44(0x43300000,uVar6 ^ 0x80000000) - dVar16) /
                       dVar17);
      pfVar8[1] = (float)((double)(float)((double)CONCAT44(0x43300000,uVar7 ^ 0x80000000) - dVar16)
                         / dVar18);
      iVar11 = iVar11 + 0xc;
      uVar10 = uVar10 + 2;
      iVar12 = iVar12 + 8;
      uVar6 = uVar6 + 1;
    } while ((int)uVar6 < 0x10);
    iVar9 = iVar9 + 0x10;
    uVar7 = uVar7 + 1;
  } while ((int)uVar7 < 8);
  FUN_80241a1c(DAT_803dd200,0xc0);
  FUN_80241a1c(DAT_803dd1fc,0x400);
  DAT_803dd208 = FUN_80023cc8(0xb40,0x7f7f7fff,0);
  FUN_802419b8(DAT_803dd208,0xb40);
  FUN_8025cd3c(DAT_803dd208,0xb40);
  FUN_802582fc();
  iVar9 = 0;
  do {
    FUN_8025889c(0x98,2,0x10);
    sVar5 = 7;
    cVar2 = '\x15';
    iVar11 = iVar9 + 0x70;
    iVar12 = iVar9 + 1 >> 0x1f;
    iVar12 = (iVar12 * 0x10 | (uint)((iVar9 + 1) * 0x10000000 + iVar12) >> 0x1c) - iVar12;
    iVar4 = iVar12 + 0x70;
    uVar1 = (undefined2)iVar12;
    iVar12 = 4;
    do {
      write_volatile_1(DAT_cc008000,cVar2);
      write_volatile_1(DAT_cc008000,cVar2);
      write_volatile_2(0xcc008000,(short)iVar9);
      write_volatile_2(0xcc008000,sVar5);
      write_volatile_2(0xcc008000,(short)iVar11);
      write_volatile_1(DAT_cc008000,cVar2);
      write_volatile_1(DAT_cc008000,cVar2);
      write_volatile_2(0xcc008000,uVar1);
      write_volatile_2(0xcc008000,sVar5);
      write_volatile_2(0xcc008000,(short)iVar4);
      cVar3 = cVar2 + -3;
      write_volatile_1(DAT_cc008000,cVar3);
      write_volatile_1(DAT_cc008000,cVar3);
      write_volatile_2(0xcc008000,(short)iVar9);
      write_volatile_2(0xcc008000,sVar5 + -1);
      write_volatile_2(0xcc008000,(short)iVar11 + -0x10);
      write_volatile_1(DAT_cc008000,cVar3);
      write_volatile_1(DAT_cc008000,cVar3);
      write_volatile_2(0xcc008000,uVar1);
      write_volatile_2(0xcc008000,sVar5 + -1);
      write_volatile_2(0xcc008000,(short)iVar4 + -0x10);
      cVar2 = cVar2 + -6;
      iVar11 = iVar11 + -0x20;
      iVar4 = iVar4 + -0x20;
      sVar5 = sVar5 + -2;
      iVar12 = iVar12 + -1;
    } while (iVar12 != 0);
    iVar9 = iVar9 + 1;
  } while (iVar9 < 0xf);
  DAT_803dd204 = FUN_8025ce04();
  FUN_80258228(1,8);
  __psq_l0(auStack8,uVar13);
  __psq_l1(auStack8,uVar13);
  __psq_l0(auStack24,uVar13);
  __psq_l1(auStack24,uVar13);
  __psq_l0(auStack40,uVar13);
  __psq_l1(auStack40,uVar13);
  __psq_l0(auStack56,uVar13);
  __psq_l1(auStack56,uVar13);
  __psq_l0(auStack72,uVar13);
  __psq_l1(auStack72,uVar13);
  FUN_80286114();
  return;
}

