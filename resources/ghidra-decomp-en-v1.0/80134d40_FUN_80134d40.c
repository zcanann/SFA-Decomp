// Function: FUN_80134d40
// Entry: 80134d40
// Size: 2772 bytes

/* WARNING: Removing unreachable block (ram,0x801357ec) */
/* WARNING: Removing unreachable block (ram,0x801357f4) */

void FUN_80134d40(undefined4 param_1,undefined4 param_2,uint param_3)

{
  int iVar1;
  ushort uVar2;
  float fVar3;
  int iVar4;
  uint uVar5;
  undefined4 uVar6;
  int iVar7;
  int iVar8;
  short sVar10;
  int iVar9;
  int iVar11;
  byte bVar12;
  undefined4 uVar13;
  double dVar14;
  undefined8 in_f30;
  double dVar15;
  undefined8 in_f31;
  ulonglong uVar16;
  double local_e8;
  double local_e0;
  double local_d8;
  double local_d0;
  double local_c8;
  double local_b8;
  double local_a8;
  double local_a0;
  double local_98;
  double local_88;
  double local_80;
  double local_78;
  double local_70;
  double local_68;
  double local_58;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar13 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar16 = FUN_802860c8();
  uVar6 = (undefined4)(uVar16 >> 0x20);
  FLOAT_803dd9c4 = FLOAT_803dd9c4 + FLOAT_803db414;
  if (FLOAT_803e22f0 < FLOAT_803dd9c4) {
    FLOAT_803dd9c4 = FLOAT_803dd9c4 - FLOAT_803e22f0;
  }
  dVar14 = (double)FUN_80294204((double)((FLOAT_803e2330 * FLOAT_803e2334 * FLOAT_803dd9c4) /
                                        FLOAT_803e22f0));
  iVar9 = DAT_803a9fa8;
  DAT_803dd9c0 = (byte)(int)((double)FLOAT_803e232c * dVar14 + (double)FLOAT_803e2328);
  if (FLOAT_803e22f8 < FLOAT_803dd9c8) {
    iVar1 = (int)DAT_803a9ff0;
    iVar11 = (int)DAT_803aa000;
    iVar7 = FUN_80285fb4((double)(FLOAT_803e2300 * FLOAT_803dd9c8));
    local_d8 = (double)CONCAT44(0x43300000,
                                iVar1 + -0x32 + (uint)*(ushort *)(DAT_803a9fb0 + 10) + 0x5a ^
                                0x80000000);
    local_d0 = (double)CONCAT44(0x43300000,iVar11 - 0x10U ^ 0x80000000);
    FUN_8007681c((double)(float)(local_d8 - DOUBLE_803e22e8),
                 (double)(float)(local_d0 - DOUBLE_803e22e8),iVar9,uVar6,0x100,
                 *(undefined2 *)(iVar9 + 10),iVar7 + 0x10,0);
    iVar9 = DAT_803a9fb0;
    iVar7 = FUN_80285fb4((double)(FLOAT_803e2300 * FLOAT_803dd9c8));
    local_c8 = (double)CONCAT44(0x43300000,iVar1 + 0x28U ^ 0x80000000);
    FUN_8007681c((double)(float)(local_c8 - DOUBLE_803e22e8),
                 (double)(float)((double)CONCAT44(0x43300000,iVar11 - 0x10U ^ 0x80000000) -
                                DOUBLE_803e22e8),iVar9,0xff,0x100,*(undefined2 *)(iVar9 + 10),
                 iVar7 + 0x10,0);
    iVar9 = DAT_803a9fb0;
    uVar2 = *(ushort *)(DAT_803a9fb0 + 10);
    iVar7 = FUN_80285fb4((double)(FLOAT_803e2300 * FLOAT_803dd9c8));
    local_b8 = (double)CONCAT44(0x43300000,
                                iVar1 + -0x32 + (uint)*(ushort *)(DAT_803a9fa8 + 10) + (uint)uVar2 +
                                0x57 ^ 0x80000000);
    FUN_8007681c((double)(float)(local_b8 - DOUBLE_803e22e8),
                 (double)(float)((double)CONCAT44(0x43300000,iVar11 - 0x10U ^ 0x80000000) -
                                DOUBLE_803e22e8),iVar9,0xff,0x100,(uint)uVar2,iVar7 + 0x10,1);
    iVar9 = DAT_803a9f98;
    iVar7 = FUN_80285fb4((double)(FLOAT_803e2300 * FLOAT_803dd9c8));
    local_a8 = (double)CONCAT44(0x43300000,iVar1 - 0xfU ^ 0x80000000);
    local_a0 = (double)CONCAT44(0x43300000,iVar11 - 0x10U ^ 0x80000000);
    FUN_8007681c((double)(float)(local_a8 - DOUBLE_803e22e8),
                 (double)(float)(local_a0 - DOUBLE_803e22e8),iVar9,0xff,0x100,
                 *(undefined2 *)(iVar9 + 10),iVar7 + 0x10,0);
  }
  iVar9 = (int)DAT_803a9ff0;
  iVar1 = (int)DAT_803aa000;
  bVar12 = DAT_803dd9c0;
  if (FLOAT_803e22f8 < FLOAT_803dd9c8) {
    bVar12 = 0xff;
  }
  local_b8 = (double)CONCAT44(0x43300000,
                              (iVar1 - (uint)*(ushort *)(DAT_803a9f9c + 0xc)) + 3 ^ 0x80000000);
  FUN_8007719c((double)(float)((double)CONCAT44(0x43300000,iVar9 - 0x18U ^ 0x80000000) -
                              DOUBLE_803e22e8),(double)(float)(local_b8 - DOUBLE_803e22e8),
               DAT_803a9f9c,0xff,0xff);
  local_c8 = (double)CONCAT44(0x43300000,iVar1 - 0x2eU ^ 0x80000000);
  FUN_8007719c((double)(float)((double)CONCAT44(0x43300000,iVar9 + 0xa1U ^ 0x80000000) -
                              DOUBLE_803e22e8),(double)(float)(local_c8 - DOUBLE_803e22e8),
               DAT_803a9fb4,bVar12,0xff);
  iVar9 = (int)DAT_803a9ff0;
  uVar5 = (uint)DAT_803aa000;
  bVar12 = DAT_803dd9c0;
  if (FLOAT_803e22f8 < FLOAT_803dd9c8) {
    bVar12 = 0xff;
  }
  local_e0 = (double)CONCAT44(0x43300000,iVar9 - 0x18U ^ 0x80000000);
  local_e8 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
  FUN_8007719c((double)(float)(local_e0 - DOUBLE_803e22e8),
               (double)(FLOAT_803e22fc +
                       FLOAT_803e2300 * FLOAT_803dd9c8 + (float)(local_e8 - DOUBLE_803e22e8)),
               DAT_803a9fa0,0xff,0xff);
  local_98 = (double)CONCAT44(0x43300000,iVar9 + 0xa1U ^ 0x80000000);
  FUN_8007719c((double)(float)(local_98 - DOUBLE_803e22e8),
               (double)(FLOAT_803e2304 +
                       FLOAT_803e2300 * FLOAT_803dd9c8 +
                       (float)((double)CONCAT44(0x43300000,uVar5 ^ 0x80000000) - DOUBLE_803e22e8)),
               DAT_803a9fb4,bVar12,0xff);
  local_88 = (double)CONCAT44(0x43300000,(uint)DAT_803dd9c0);
  FUN_80019908(0xff,0xff,0xff,
               (int)((local_88 - DOUBLE_803e2310) * (DOUBLE_803e2308 - (double)FLOAT_803dd9c8)));
  FUN_80016870(0x3da);
  local_70 = (double)CONCAT44(0x43300000,(int)DAT_803a9ff0 - 0x32U ^ 0x80000000);
  local_68 = (double)CONCAT44(0x43300000,0xfe - (*(ushort *)(DAT_803a9fa4 + 10) >> 1) ^ 0x80000000);
  FUN_8007719c((double)(float)(local_70 - DOUBLE_803e22e8),
               (double)(float)(local_68 - DOUBLE_803e22e8),DAT_803a9fa4,0xff,0xff);
  if ((FLOAT_803e2338 <= FLOAT_803dd9c8) && ((uVar16 & 0xff) == 0)) {
    iVar9 = (int)DAT_803a9ff0;
    iVar1 = (int)DAT_803aa000;
    iVar11 = 0;
    dVar15 = (double)FLOAT_803e2300;
    dVar14 = DOUBLE_803e22e8;
    do {
      iVar7 = DAT_803a9fa8;
      iVar8 = FUN_80285fb4((double)(float)(dVar15 * (double)FLOAT_803dd9c8));
      iVar4 = iVar11 + 1;
      local_68 = (double)CONCAT44(0x43300000,
                                  iVar9 + (uint)*(ushort *)(DAT_803a9fb0 + 10) + 0x28 + iVar4 * -4 ^
                                  0x80000000);
      local_70 = (double)CONCAT44(0x43300000,iVar1 + -0x10 + iVar4 * -3 ^ 0x80000000);
      FUN_8007681c((double)(float)(local_68 - dVar14),(double)(float)(local_70 - dVar14),iVar7,
                   (int)(uint)DAT_803dd9c0 >> (iVar11 + 3U & 0x3f) & 0xff,0x100,
                   (uint)*(ushort *)(iVar7 + 10) + iVar4 * 8,iVar8 + iVar4 * 6 + 0x10,4);
      iVar11 = iVar11 + 1;
    } while (iVar11 < 4);
  }
  if ((FLOAT_803e22f8 < FLOAT_803dd9c8) && (sVar10 = FUN_80130124(), sVar10 != -1)) {
    iVar9 = FUN_800173c8();
    if ((uVar16 & 0xff) == 0) {
      local_68 = (double)CONCAT44(0x43300000,(int)DAT_803a9ff0 + 0x2fU ^ 0x80000000);
      local_70 = (double)CONCAT44(0x43300000,
                                  ((int)*(short *)(iVar9 + 0x16) + (int)DAT_803aa000) - 1U ^
                                  0x80000000);
      FUN_8007719c((double)(float)(local_68 - DOUBLE_803e22e8),
                   (double)(float)(local_70 - DOUBLE_803e22e8),DAT_803a9fac,uVar6,0xff);
    }
  }
  uVar5 = (uint)DAT_803dd9c0;
  local_70 = (double)CONCAT44(0x43300000,(int)(FLOAT_803e22f0 * FLOAT_803dd9b0) - 0x50U ^ 0x80000000
                             );
  local_80 = (double)CONCAT44(0x43300000,
                              (int)(FLOAT_803e22f4 * FLOAT_803dd9b4) + 0x1e0U ^ 0x80000000);
  FUN_8007681c((double)(float)(local_70 - DOUBLE_803e22e8),
               (double)(float)(local_80 - DOUBLE_803e22e8),DAT_803a9fe0,0xff,0x100,
               *(undefined2 *)(DAT_803a9fe0 + 10),*(undefined2 *)(DAT_803a9fe0 + 0xc),1);
  iVar9 = *(int *)(&DAT_803a9fb8 + ((int)(uVar5 << 3) >> 8) * 4);
  local_a0 = (double)CONCAT44(0x43300000,
                              (int)(FLOAT_803e22f4 * FLOAT_803dd9b4) + 0x1e0U ^ 0x80000000);
  FUN_8007681c((double)(float)((double)CONCAT44(0x43300000,
                                                ((int)(FLOAT_803e22f0 * FLOAT_803dd9b0) +
                                                (uint)*(ushort *)(DAT_803a9fe0 + 10)) - 0x4a ^
                                                0x80000000) - DOUBLE_803e22e8),
               (double)(float)(local_a0 - DOUBLE_803e22e8),iVar9,0xff,0x100,
               *(undefined2 *)(iVar9 + 10),*(undefined2 *)(iVar9 + 0xc),0);
  FUN_8007681c((double)(float)((double)CONCAT44(0x43300000,
                                                (0x280 - ((int)(FLOAT_803e22f0 * FLOAT_803dd9b0) +
                                                         -0x50)) -
                                                (uint)*(ushort *)(DAT_803a9fe0 + 10) ^ 0x80000000) -
                              DOUBLE_803e22e8),
               (double)(float)((double)CONCAT44(0x43300000,
                                                (int)(FLOAT_803e22f4 * FLOAT_803dd9b4) + 0x1e0U ^
                                                0x80000000) - DOUBLE_803e22e8),DAT_803a9fe0,0xff,
               0x100,(uint)*(ushort *)(DAT_803a9fe0 + 10),*(undefined2 *)(DAT_803a9fe0 + 0xc),0);
  iVar9 = *(int *)(&DAT_803a9fb8 + ((int)(uVar5 << 3) >> 8) * 4);
  local_d0 = (double)CONCAT44(0x43300000,
                              ((0x27a - ((int)(FLOAT_803e22f0 * FLOAT_803dd9b0) + -0x50)) -
                              (uint)*(ushort *)(DAT_803a9fe0 + 10)) - (uint)*(ushort *)(iVar9 + 10)
                              ^ 0x80000000);
  local_e0 = (double)CONCAT44(0x43300000,
                              (int)(FLOAT_803e22f4 * FLOAT_803dd9b4) + 0x1e0U ^ 0x80000000);
  FUN_8007681c((double)(float)(local_d0 - DOUBLE_803e22e8),
               (double)(float)(local_e0 - DOUBLE_803e22e8),iVar9,0xff,0x100,
               (uint)*(ushort *)(iVar9 + 10),*(undefined2 *)(iVar9 + 0xc),1);
  fVar3 = FLOAT_803dd9b4;
  if (FLOAT_803dd9b0 < FLOAT_803dd9b4) {
    fVar3 = FLOAT_803dd9b0;
  }
  local_e8 = (double)CONCAT44(0x43300000,
                              (0x280 - ((int)((uint)*(ushort *)(DAT_803dd9d4 + 10) * 0xbe) >> 8)) /
                              2 ^ 0x80000000);
  local_58 = (double)CONCAT44(0x43300000,(int)(FLOAT_803e2340 * fVar3 + FLOAT_803e233c) ^ 0x80000000
                             );
  FUN_8007719c((double)(float)(local_e8 - DOUBLE_803e22e8),
               (double)(float)(local_58 - DOUBLE_803e22e8),DAT_803dd9d4,0xff,0xbe);
  if ((param_3 & 0xff) != 0) {
    iVar9 = (int)DAT_803a9ff0;
    iVar1 = (int)DAT_803aa000;
    local_68 = (double)CONCAT44(0x43300000,iVar9 + 0x2fU ^ 0x80000000);
    local_70 = (double)CONCAT44(0x43300000,iVar1 + 0x14U ^ 0x80000000);
    FUN_8007719c((double)(float)(local_68 - DOUBLE_803e22e8),
                 (double)(float)(local_70 - DOUBLE_803e22e8),DAT_803a9fdc,0xff,0xff);
    local_78 = (double)CONCAT44(0x43300000,iVar9 + 0x2fU ^ 0x80000000);
    local_80 = (double)CONCAT44(0x43300000,iVar1 + 0x4bU ^ 0x80000000);
    FUN_8007719c((double)(float)(local_78 - DOUBLE_803e22e8),
                 (double)(float)(local_80 - DOUBLE_803e22e8),DAT_803a9fd8,0xff,0xff);
  }
  __psq_l0(auStack8,uVar13);
  __psq_l1(auStack8,uVar13);
  __psq_l0(auStack24,uVar13);
  __psq_l1(auStack24,uVar13);
  FUN_80286114();
  return;
}

