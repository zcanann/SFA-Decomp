// Function: FUN_801350c8
// Entry: 801350c8
// Size: 2772 bytes

/* WARNING: Removing unreachable block (ram,0x80135b7c) */
/* WARNING: Removing unreachable block (ram,0x80135b74) */
/* WARNING: Removing unreachable block (ram,0x801350e0) */
/* WARNING: Removing unreachable block (ram,0x801350d8) */

void FUN_801350c8(undefined4 param_1,undefined4 param_2,uint param_3)

{
  int iVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  ushort uVar9;
  undefined *puVar7;
  int iVar8;
  uint uVar10;
  int iVar11;
  uint uVar12;
  double dVar13;
  undefined8 uVar14;
  double dVar15;
  double dVar16;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  ulonglong uVar17;
  undefined8 local_e8;
  undefined8 local_e0;
  undefined8 local_d8;
  undefined8 local_d0;
  undefined8 local_c8;
  undefined8 local_b8;
  undefined8 local_a8;
  undefined8 local_a0;
  undefined8 local_98;
  undefined8 local_88;
  undefined8 local_80;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined8 local_58;
  
  uVar17 = FUN_8028682c();
  uVar4 = (uint)(uVar17 >> 0x20);
  FLOAT_803de644 = FLOAT_803de644 + FLOAT_803dc074;
  if (FLOAT_803e2f80 < FLOAT_803de644) {
    FLOAT_803de644 = FLOAT_803de644 - FLOAT_803e2f80;
  }
  dVar13 = (double)FUN_80294964();
  iVar8 = DAT_803aac08;
  DAT_803de640 = (byte)(int)((double)FLOAT_803e2fbc * dVar13 + (double)FLOAT_803e2fb8);
  if (FLOAT_803e2f88 < FLOAT_803de648) {
    iVar1 = (int)DAT_803aac50;
    iVar11 = (int)DAT_803aac60;
    iVar5 = FUN_80286718((double)(FLOAT_803e2f90 * FLOAT_803de648));
    local_d8 = (double)CONCAT44(0x43300000,
                                iVar1 + -0x32 + (uint)*(ushort *)(DAT_803aac10 + 10) + 0x5a ^
                                0x80000000);
    local_d0 = (double)CONCAT44(0x43300000,iVar11 - 0x10U ^ 0x80000000);
    FUN_80076998((double)(float)(local_d8 - DOUBLE_803e2f78),
                 (double)(float)(local_d0 - DOUBLE_803e2f78),iVar8,uVar4,0x100,
                 (uint)*(ushort *)(iVar8 + 10),iVar5 + 0x10,0);
    iVar8 = DAT_803aac10;
    iVar5 = FUN_80286718((double)(FLOAT_803e2f90 * FLOAT_803de648));
    local_c8 = (double)CONCAT44(0x43300000,iVar1 + 0x28U ^ 0x80000000);
    FUN_80076998((double)(float)(local_c8 - DOUBLE_803e2f78),
                 (double)(float)((double)CONCAT44(0x43300000,iVar11 - 0x10U ^ 0x80000000) -
                                DOUBLE_803e2f78),iVar8,0xff,0x100,(uint)*(ushort *)(iVar8 + 10),
                 iVar5 + 0x10,0);
    iVar8 = DAT_803aac10;
    uVar9 = *(ushort *)(DAT_803aac10 + 10);
    iVar5 = FUN_80286718((double)(FLOAT_803e2f90 * FLOAT_803de648));
    local_b8 = (double)CONCAT44(0x43300000,
                                iVar1 + -0x32 + (uint)*(ushort *)(DAT_803aac08 + 10) + (uint)uVar9 +
                                0x57 ^ 0x80000000);
    FUN_80076998((double)(float)(local_b8 - DOUBLE_803e2f78),
                 (double)(float)((double)CONCAT44(0x43300000,iVar11 - 0x10U ^ 0x80000000) -
                                DOUBLE_803e2f78),iVar8,0xff,0x100,(uint)uVar9,iVar5 + 0x10,1);
    iVar8 = DAT_803aabf8;
    iVar5 = FUN_80286718((double)(FLOAT_803e2f90 * FLOAT_803de648));
    local_a8 = (double)CONCAT44(0x43300000,iVar1 - 0xfU ^ 0x80000000);
    local_a0 = (double)CONCAT44(0x43300000,iVar11 - 0x10U ^ 0x80000000);
    FUN_80076998((double)(float)(local_a8 - DOUBLE_803e2f78),
                 (double)(float)(local_a0 - DOUBLE_803e2f78),iVar8,0xff,0x100,
                 (uint)*(ushort *)(iVar8 + 10),iVar5 + 0x10,0);
  }
  iVar8 = (int)DAT_803aac50;
  iVar1 = (int)DAT_803aac60;
  if (FLOAT_803de648 <= FLOAT_803e2f88) {
    uVar12 = (uint)DAT_803de640;
  }
  else {
    uVar12 = 0xff;
  }
  local_b8 = (double)CONCAT44(0x43300000,
                              (iVar1 - (uint)*(ushort *)(DAT_803aabfc + 0xc)) + 3 ^ 0x80000000);
  FUN_80077318((double)(float)((double)CONCAT44(0x43300000,iVar8 - 0x18U ^ 0x80000000) -
                              DOUBLE_803e2f78),(double)(float)(local_b8 - DOUBLE_803e2f78),
               DAT_803aabfc,0xff,0xff);
  local_c8 = (double)CONCAT44(0x43300000,iVar1 - 0x2eU ^ 0x80000000);
  FUN_80077318((double)(float)((double)CONCAT44(0x43300000,iVar8 + 0xa1U ^ 0x80000000) -
                              DOUBLE_803e2f78),(double)(float)(local_c8 - DOUBLE_803e2f78),
               DAT_803aac14,uVar12,0xff);
  iVar8 = (int)DAT_803aac50;
  uVar12 = (uint)DAT_803aac60;
  if (FLOAT_803de648 <= FLOAT_803e2f88) {
    uVar10 = (uint)DAT_803de640;
  }
  else {
    uVar10 = 0xff;
  }
  local_e0 = (double)CONCAT44(0x43300000,iVar8 - 0x18U ^ 0x80000000);
  local_e8 = (double)CONCAT44(0x43300000,uVar12 ^ 0x80000000);
  FUN_80077318((double)(float)(local_e0 - DOUBLE_803e2f78),
               (double)(FLOAT_803e2f8c +
                       FLOAT_803e2f90 * FLOAT_803de648 + (float)(local_e8 - DOUBLE_803e2f78)),
               DAT_803aac00,0xff,0xff);
  local_98 = (double)CONCAT44(0x43300000,iVar8 + 0xa1U ^ 0x80000000);
  dVar16 = (double)FLOAT_803e2f94;
  dVar15 = (double)FLOAT_803e2f90;
  dVar13 = DOUBLE_803e2f78;
  FUN_80077318((double)(float)(local_98 - DOUBLE_803e2f78),
               (double)(float)(dVar16 + (double)(float)(dVar15 * (double)FLOAT_803de648 +
                                                       (double)(float)((double)CONCAT44(0x43300000,
                                                                                        uVar12 ^ 
                                                  0x80000000) - DOUBLE_803e2f78))),DAT_803aac14,
               uVar10,0xff);
  local_88 = (double)CONCAT44(0x43300000,(uint)DAT_803de640);
  local_88 = local_88 - DOUBLE_803e2fa0;
  uVar14 = FUN_80019940(0xff,0xff,0xff,
                        (byte)(int)(local_88 * (DOUBLE_803e2f98 - (double)FLOAT_803de648)));
  FUN_800168a8(uVar14,local_88,dVar15,dVar16,dVar13,in_f6,in_f7,in_f8,0x3da);
  local_70 = (double)CONCAT44(0x43300000,(int)DAT_803aac50 - 0x32U ^ 0x80000000);
  local_68 = (double)CONCAT44(0x43300000,0xfe - (*(ushort *)(DAT_803aac04 + 10) >> 1) ^ 0x80000000);
  FUN_80077318((double)(float)(local_70 - DOUBLE_803e2f78),
               (double)(float)(local_68 - DOUBLE_803e2f78),DAT_803aac04,0xff,0xff);
  if ((FLOAT_803e2fc8 <= FLOAT_803de648) && ((uVar17 & 0xff) == 0)) {
    iVar8 = (int)DAT_803aac50;
    iVar1 = (int)DAT_803aac60;
    iVar11 = 0;
    dVar15 = (double)FLOAT_803e2f90;
    dVar13 = DOUBLE_803e2f78;
    do {
      iVar5 = DAT_803aac08;
      iVar6 = FUN_80286718((double)(float)(dVar15 * (double)FLOAT_803de648));
      iVar3 = iVar11 + 1;
      local_68 = (double)CONCAT44(0x43300000,
                                  iVar8 + (uint)*(ushort *)(DAT_803aac10 + 10) + 0x28 + iVar3 * -4 ^
                                  0x80000000);
      local_70 = (double)CONCAT44(0x43300000,iVar1 + -0x10 + iVar3 * -3 ^ 0x80000000);
      FUN_80076998((double)(float)(local_68 - dVar13),(double)(float)(local_70 - dVar13),iVar5,
                   (int)(uint)DAT_803de640 >> (iVar11 + 3U & 0x3f) & 0xff,0x100,
                   (uint)*(ushort *)(iVar5 + 10) + iVar3 * 8,iVar6 + iVar3 * 6 + 0x10,4);
      iVar11 = iVar11 + 1;
    } while (iVar11 < 4);
  }
  if (FLOAT_803e2f88 < FLOAT_803de648) {
    uVar9 = FUN_8013047c();
    if (uVar9 != 0xffff) {
      puVar7 = FUN_80017400((uint)uVar9);
      if ((uVar17 & 0xff) == 0) {
        local_68 = (double)CONCAT44(0x43300000,(int)DAT_803aac50 + 0x2fU ^ 0x80000000);
        local_70 = (double)CONCAT44(0x43300000,
                                    ((int)*(short *)(puVar7 + 0x16) + (int)DAT_803aac60) - 1U ^
                                    0x80000000);
        FUN_80077318((double)(float)(local_68 - DOUBLE_803e2f78),
                     (double)(float)(local_70 - DOUBLE_803e2f78),DAT_803aac0c,uVar4,0xff);
      }
    }
  }
  uVar4 = (uint)DAT_803de640;
  local_70 = (double)CONCAT44(0x43300000,(int)(FLOAT_803e2f80 * FLOAT_803de630) - 0x50U ^ 0x80000000
                             );
  local_80 = (double)CONCAT44(0x43300000,
                              (int)(FLOAT_803e2f84 * FLOAT_803de634) + 0x1e0U ^ 0x80000000);
  FUN_80076998((double)(float)(local_70 - DOUBLE_803e2f78),
               (double)(float)(local_80 - DOUBLE_803e2f78),DAT_803aac40,0xff,0x100,
               (uint)*(ushort *)(DAT_803aac40 + 10),(uint)*(ushort *)(DAT_803aac40 + 0xc),1);
  iVar8 = *(int *)(&DAT_803aac18 + ((int)(uVar4 << 3) >> 8) * 4);
  local_a0 = (double)CONCAT44(0x43300000,
                              (int)(FLOAT_803e2f84 * FLOAT_803de634) + 0x1e0U ^ 0x80000000);
  FUN_80076998((double)(float)((double)CONCAT44(0x43300000,
                                                ((int)(FLOAT_803e2f80 * FLOAT_803de630) +
                                                (uint)*(ushort *)(DAT_803aac40 + 10)) - 0x4a ^
                                                0x80000000) - DOUBLE_803e2f78),
               (double)(float)(local_a0 - DOUBLE_803e2f78),iVar8,0xff,0x100,
               (uint)*(ushort *)(iVar8 + 10),(uint)*(ushort *)(iVar8 + 0xc),0);
  FUN_80076998((double)(float)((double)CONCAT44(0x43300000,
                                                (0x280 - ((int)(FLOAT_803e2f80 * FLOAT_803de630) +
                                                         -0x50)) -
                                                (uint)*(ushort *)(DAT_803aac40 + 10) ^ 0x80000000) -
                              DOUBLE_803e2f78),
               (double)(float)((double)CONCAT44(0x43300000,
                                                (int)(FLOAT_803e2f84 * FLOAT_803de634) + 0x1e0U ^
                                                0x80000000) - DOUBLE_803e2f78),DAT_803aac40,0xff,
               0x100,(uint)*(ushort *)(DAT_803aac40 + 10),(uint)*(ushort *)(DAT_803aac40 + 0xc),0);
  iVar8 = *(int *)(&DAT_803aac18 + ((int)(uVar4 << 3) >> 8) * 4);
  local_d0 = (double)CONCAT44(0x43300000,
                              ((0x27a - ((int)(FLOAT_803e2f80 * FLOAT_803de630) + -0x50)) -
                              (uint)*(ushort *)(DAT_803aac40 + 10)) - (uint)*(ushort *)(iVar8 + 10)
                              ^ 0x80000000);
  local_e0 = (double)CONCAT44(0x43300000,
                              (int)(FLOAT_803e2f84 * FLOAT_803de634) + 0x1e0U ^ 0x80000000);
  FUN_80076998((double)(float)(local_d0 - DOUBLE_803e2f78),
               (double)(float)(local_e0 - DOUBLE_803e2f78),iVar8,0xff,0x100,
               (uint)*(ushort *)(iVar8 + 10),(uint)*(ushort *)(iVar8 + 0xc),1);
  fVar2 = FLOAT_803de634;
  if (FLOAT_803de630 < FLOAT_803de634) {
    fVar2 = FLOAT_803de630;
  }
  local_e8 = (double)CONCAT44(0x43300000,
                              (0x280 - ((int)((uint)*(ushort *)(DAT_803de654 + 10) * 0xbe) >> 8)) /
                              2 ^ 0x80000000);
  local_58 = (double)CONCAT44(0x43300000,(int)(FLOAT_803e2fd0 * fVar2 + FLOAT_803e2fcc) ^ 0x80000000
                             );
  FUN_80077318((double)(float)(local_e8 - DOUBLE_803e2f78),
               (double)(float)(local_58 - DOUBLE_803e2f78),DAT_803de654,0xff,0xbe);
  if ((param_3 & 0xff) != 0) {
    iVar8 = (int)DAT_803aac50;
    iVar1 = (int)DAT_803aac60;
    local_68 = (double)CONCAT44(0x43300000,iVar8 + 0x2fU ^ 0x80000000);
    local_70 = (double)CONCAT44(0x43300000,iVar1 + 0x14U ^ 0x80000000);
    FUN_80077318((double)(float)(local_68 - DOUBLE_803e2f78),
                 (double)(float)(local_70 - DOUBLE_803e2f78),DAT_803aac3c,0xff,0xff);
    local_78 = (double)CONCAT44(0x43300000,iVar8 + 0x2fU ^ 0x80000000);
    local_80 = (double)CONCAT44(0x43300000,iVar1 + 0x4bU ^ 0x80000000);
    FUN_80077318((double)(float)(local_78 - DOUBLE_803e2f78),
                 (double)(float)(local_80 - DOUBLE_803e2f78),DAT_803aac38,0xff,0xff);
  }
  FUN_80286878();
  return;
}

