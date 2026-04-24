// Function: FUN_802b0ea4
// Entry: 802b0ea4
// Size: 2584 bytes

/* WARNING: Removing unreachable block (ram,0x802b188c) */
/* WARNING: Removing unreachable block (ram,0x802b1894) */

void FUN_802b0ea4(short *param_1,int param_2,int param_3)

{
  float fVar1;
  float fVar2;
  short sVar3;
  float fVar4;
  uint uVar5;
  undefined4 uVar6;
  uint uVar7;
  int iVar8;
  int iVar9;
  undefined4 uVar10;
  double dVar11;
  undefined8 in_f30;
  undefined8 in_f31;
  double dVar12;
  double local_78;
  double local_70;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar10 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  if ((*(uint *)(param_2 + 0x360) & 0x800000) != 0) {
    sVar3 = *param_1;
    *(short *)(param_2 + 0x484) = sVar3;
    *(short *)(param_2 + 0x478) = sVar3;
    *(int *)(param_2 + 0x494) = (int)sVar3;
    *(float *)(param_3 + 0x298) = FLOAT_803e7ea4;
  }
  *(undefined4 *)(param_3 + 0x29c) = *(undefined4 *)(param_3 + 0x298);
  *(undefined2 *)(param_2 + 0x490) = *(undefined2 *)(param_2 + 0x484);
  *(undefined2 *)(param_2 + 0x492) = *(undefined2 *)(param_2 + 0x478);
  dVar11 = (double)FUN_802931a0((double)(*(float *)(param_3 + 0x290) * *(float *)(param_3 + 0x290) +
                                        *(float *)(param_3 + 0x28c) * *(float *)(param_3 + 0x28c)));
  *(float *)(param_3 + 0x298) = (float)dVar11;
  if (FLOAT_803e7fa8 < *(float *)(param_3 + 0x298)) {
    *(float *)(param_3 + 0x298) = FLOAT_803e7fa8;
  }
  *(float *)(param_3 + 0x298) = *(float *)(param_3 + 0x298) / FLOAT_803e7fa8;
  *(float *)(param_2 + 0x470) = *(float *)(param_3 + 0x298) - *(float *)(param_3 + 0x29c);
  if (FLOAT_803e7f6c <= *(float *)(param_3 + 0x298)) {
    uVar7 = FUN_800217c0((double)*(float *)(param_3 + 0x290),-(double)*(float *)(param_3 + 0x28c));
    *(uint *)(param_2 + 0x474) = uVar7 & 0xffff;
    *(int *)(param_2 + 0x474) = *(int *)(param_2 + 0x474) - (int)*(short *)(param_3 + 0x330);
    if ((*(uint *)(param_2 + 0x360) & 0x1000000) == 0) {
      *(undefined4 *)(param_2 + 0x494) = *(undefined4 *)(param_2 + 0x474);
    }
  }
  else {
    *(float *)(param_3 + 0x298) = FLOAT_803e7ea4;
    *(undefined4 *)(param_2 + 0x474) = *(undefined4 *)(param_2 + 0x494);
  }
  dVar11 = DOUBLE_803e7ec0;
  uVar7 = *(int *)(param_2 + 0x474) - ((int)*(short *)(param_2 + 0x484) & 0xffffU);
  if (0x8000 < (int)uVar7) {
    uVar7 = uVar7 - 0xffff;
  }
  if ((int)uVar7 < -0x8000) {
    uVar7 = uVar7 + 0xffff;
  }
  local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
  *(int *)(param_2 + 0x48c) = (int)((float)(local_78 - DOUBLE_803e7ec0) / FLOAT_803e7f00);
  if (*(float *)(param_2 + 0x85c) != FLOAT_803e7ea4) {
    fVar2 = *(float *)(param_2 + 0x85c) * *(float *)(param_3 + 0x280);
    uVar5 = *(uint *)(param_2 + 0x48c) ^ 0x80000000;
    local_70 = (double)CONCAT44(0x43300000,uVar5);
    if (((float)(local_70 - dVar11) < fVar2) &&
       (local_70 = (double)CONCAT44(0x43300000,uVar5), -fVar2 < (float)(local_70 - dVar11))) {
      *(undefined4 *)(param_2 + 0x48c) = 0;
    }
  }
  if ((int)uVar7 < 0) {
    *(int *)(param_2 + 0x488) = -*(int *)(param_2 + 0x48c);
  }
  else {
    *(undefined4 *)(param_2 + 0x488) = *(undefined4 *)(param_2 + 0x48c);
  }
  if (FLOAT_803e7f6c <= *(float *)(param_3 + 0x298)) {
    uVar5 = uVar7 + 0xa000;
    if ((int)uVar5 < 0) {
      uVar5 = uVar7 + 0x19fff;
    }
    if (0xffff < (int)uVar5) {
      uVar5 = uVar5 - 0xffff;
    }
    *(char *)(param_3 + 0x34b) =
         '\x04' - ((char)((int)uVar5 >> 0xe) + ((int)uVar5 < 0 && (uVar5 & 0x3fff) != 0));
  }
  else {
    *(undefined *)(param_3 + 0x34b) = 0;
  }
  dVar11 = DOUBLE_803e7ec0;
  uVar7 = *(int *)(param_2 + 0x474) - ((int)*(short *)(param_2 + 0x478) & 0xffffU);
  if (0x8000 < (int)uVar7) {
    uVar7 = uVar7 - 0xffff;
  }
  if ((int)uVar7 < -0x8000) {
    uVar7 = uVar7 + 0xffff;
  }
  local_70 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
  *(int *)(param_2 + 0x480) = (int)((float)(local_70 - DOUBLE_803e7ec0) / FLOAT_803e7f00);
  if (*(float *)(param_2 + 0x85c) != FLOAT_803e7ea4) {
    fVar2 = *(float *)(param_2 + 0x85c) * *(float *)(param_3 + 0x280);
    uVar5 = *(uint *)(param_2 + 0x480) ^ 0x80000000;
    local_70 = (double)CONCAT44(0x43300000,uVar5);
    if (((float)(local_70 - dVar11) < fVar2) &&
       (local_70 = (double)CONCAT44(0x43300000,uVar5), -fVar2 < (float)(local_70 - dVar11))) {
      *(undefined4 *)(param_2 + 0x480) = 0;
    }
  }
  if ((int)uVar7 < 0) {
    *(int *)(param_2 + 0x47c) = -*(int *)(param_2 + 0x480);
  }
  else {
    *(undefined4 *)(param_2 + 0x47c) = *(undefined4 *)(param_2 + 0x480);
  }
  uVar7 = *(int *)(param_2 + 0x474) - ((int)*(short *)(param_2 + 0x4d4) & 0xffffU);
  if (0x8000 < (int)uVar7) {
    uVar7 = uVar7 - 0xffff;
  }
  if ((int)uVar7 < -0x8000) {
    uVar7 = uVar7 + 0xffff;
  }
  local_70 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
  *(int *)(param_2 + 0x49c) = (int)((float)(local_70 - DOUBLE_803e7ec0) / FLOAT_803e7f00);
  if ((int)uVar7 < 0) {
    *(int *)(param_2 + 0x498) = -*(int *)(param_2 + 0x49c);
  }
  else {
    *(undefined4 *)(param_2 + 0x498) = *(undefined4 *)(param_2 + 0x49c);
  }
  uVar6 = (**(code **)(*DAT_803dca50 + 0x40))();
  *(undefined4 *)(param_2 + 0x4b8) = uVar6;
  iVar9 = *(int *)(param_2 + 0x4b8);
  if (iVar9 != 0) {
    dVar12 = (double)(*(float *)(iVar9 + 0xc) - *(float *)(param_1 + 6));
    dVar11 = (double)(*(float *)(iVar9 + 0x14) - *(float *)(param_1 + 10));
    uVar7 = FUN_800217c0(-dVar12,-dVar11);
    *(uint *)(param_2 + 0x4ac) = uVar7 & 0xffff;
    dVar11 = (double)FUN_802931a0((double)(float)(dVar12 * dVar12 + (double)(float)(dVar11 * dVar11)
                                                 ));
    *(float *)(param_2 + 0x4b0) = (float)dVar11;
    *(ushort *)(param_2 + 0x4b4) = *(byte *)(*(int *)(*(int *)(iVar9 + 0x50) + 0x40) + 0x10) & 0xf;
  }
  uVar7 = *(int *)(param_2 + 0x4ac) - ((int)*(short *)(param_2 + 0x478) & 0xffffU);
  if (0x8000 < (int)uVar7) {
    uVar7 = uVar7 - 0xffff;
  }
  if ((int)uVar7 < -0x8000) {
    uVar7 = uVar7 + 0xffff;
  }
  local_70 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
  *(int *)(param_2 + 0x4a4) = (int)(local_70 - DOUBLE_803e7ec0);
  if ((int)uVar7 < 0) {
    *(int *)(param_2 + 0x4a8) = -*(int *)(param_2 + 0x4a4);
  }
  else {
    *(undefined4 *)(param_2 + 0x4a8) = *(undefined4 *)(param_2 + 0x4a4);
  }
  if ((*(byte *)(param_2 + 0x3f1) >> 5 & 1) == 0) {
    dVar12 = (double)*(float *)(param_3 + 0x280);
    dVar11 = (double)FLOAT_803e7ea4;
    if ((dVar11 <= dVar12) && (dVar11 = dVar12, (double)*(float *)(param_2 + 0x404) < dVar12)) {
      dVar11 = (double)*(float *)(param_2 + 0x404);
    }
    dVar12 = dVar11 * (double)*(float *)(param_2 + 0x7e0);
    uVar7 = (uint)dVar12;
    local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
    dVar12 = (double)FUN_80010c64((double)((float)dVar12 - (float)(local_78 - DOUBLE_803e7ec0)),
                                  *(int *)(param_2 + 0x450) + (uVar7 + 1) * 4,0);
    *(float *)(param_2 + 0x438) = (float)((double)FLOAT_803e7ee0 / dVar12);
  }
  else {
    dVar12 = (double)FUN_802931a0((double)(*(float *)(param_3 + 0x280) * *(float *)(param_3 + 0x280)
                                          + *(float *)(param_3 + 0x284) *
                                            *(float *)(param_3 + 0x284)));
    dVar11 = (double)FLOAT_803e7ea4;
    if ((dVar11 <= dVar12) && (dVar11 = dVar12, (double)*(float *)(param_2 + 0x404) < dVar12)) {
      dVar11 = (double)*(float *)(param_2 + 0x404);
    }
    if (FLOAT_803e7ee0 == *(float *)(param_2 + 0x82c)) {
      *(float *)(param_2 + 0x438) = FLOAT_803e7f44;
    }
    else {
      dVar12 = dVar11 * (double)*(float *)(param_2 + 0x7e0);
      uVar7 = (uint)dVar12;
      local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
      dVar12 = (double)FUN_80010c64((double)((float)dVar12 - (float)(local_78 - DOUBLE_803e7ec0)),
                                    *(int *)(param_2 + 0x450) + (uVar7 + 1) * 4,0);
      *(float *)(param_2 + 0x438) = (float)((double)FLOAT_803e7ee0 / dVar12);
    }
  }
  dVar12 = dVar11 * (double)*(float *)(param_2 + 0x7e0);
  uVar7 = (uint)dVar12;
  local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
  dVar12 = (double)FUN_80010c64((double)((float)dVar12 - (float)(local_78 - DOUBLE_803e7ec0)),
                                *(int *)(param_2 + 0x454) + (uVar7 + 1) * 4,0);
  *(float *)(param_2 + 0x428) = (float)dVar12;
  dVar12 = dVar11 * (double)*(float *)(param_2 + 0x7e0);
  uVar7 = (uint)dVar12;
  dVar12 = (double)FUN_80010c64((double)((float)dVar12 -
                                        (float)((double)CONCAT44(0x43300000,uVar7 ^ 0x80000000) -
                                               DOUBLE_803e7ec0)),
                                *(int *)(param_2 + 0x458) + (uVar7 + 1) * 4,0);
  *(float *)(param_2 + 0x42c) = (float)dVar12;
  dVar12 = dVar11 * (double)*(float *)(param_2 + 0x7e0);
  uVar7 = (uint)dVar12;
  dVar12 = (double)FUN_80010c64((double)((float)dVar12 -
                                        (float)((double)CONCAT44(0x43300000,uVar7 ^ 0x80000000) -
                                               DOUBLE_803e7ec0)),
                                *(int *)(param_2 + 0x45c) + (uVar7 + 1) * 4,0);
  *(float *)(param_2 + 0x430) = (float)dVar12;
  dVar11 = dVar11 * (double)*(float *)(param_2 + 0x7e0);
  uVar7 = (uint)dVar11;
  dVar11 = (double)FUN_80010c64((double)((float)dVar11 -
                                        (float)((double)CONCAT44(0x43300000,uVar7 ^ 0x80000000) -
                                               DOUBLE_803e7ec0)),
                                *(int *)(param_2 + 0x460) + (uVar7 + 1) * 4,0);
  *(float *)(param_2 + 0x434) = (float)dVar11;
  fVar2 = FLOAT_803e80e4;
  if ((*(byte *)(param_2 + 0x3f0) >> 5 & 1) == 0) {
    if (FLOAT_803e7ee0 != *(float *)(param_2 + 0x834)) {
      fVar2 = *(float *)(*(int *)(param_2 + 0x400) + 0x10);
      fVar4 = (*(float *)(param_3 + 0x280) - fVar2) / (*(float *)(param_2 + 0x404) - fVar2);
      fVar2 = FLOAT_803e7ea4;
      if ((FLOAT_803e7ea4 <= fVar4) && (fVar2 = fVar4, FLOAT_803e7ee0 < fVar4)) {
        fVar2 = FLOAT_803e7ee0;
      }
      *(float *)(param_2 + 0x430) =
           *(float *)(param_2 + 0x430) *
           ((*(float *)(param_2 + 0x834) - FLOAT_803e7ee0) * fVar2 + FLOAT_803e7ee0);
    }
  }
  else {
    *(float *)(param_2 + 0x428) = *(float *)(param_2 + 0x428) * FLOAT_803e80e4;
    *(float *)(param_2 + 0x430) = *(float *)(param_2 + 0x430) * fVar2;
    *(float *)(param_2 + 0x438) = *(float *)(param_2 + 0x438) * FLOAT_803e7f44;
  }
  if (*(int *)(param_2 + 0x464) == 0) {
    *(float *)(param_2 + 0x420) = FLOAT_803e7ee0;
  }
  else {
    iVar8 = *(int *)(param_2 + 0x47c);
    iVar9 = iVar8 / 5 + (iVar8 >> 0x1f);
    dVar11 = (double)FUN_80010c64((double)((float)((double)CONCAT44(0x43300000,
                                                                    iVar8 + (iVar9 - (iVar9 >> 0x1f)
                                                                            ) * -5 ^ 0x80000000) -
                                                  DOUBLE_803e7ec0) / FLOAT_803e7f10),
                                  *(int *)(param_2 + 0x464) + ((iVar9 - (iVar9 >> 0x1f)) + 1) * 4,0)
    ;
    *(float *)(param_2 + 0x420) = (float)dVar11;
  }
  fVar4 = FLOAT_803e7ee0;
  *(float *)(param_2 + 0x420) = FLOAT_803e7ee0;
  fVar2 = FLOAT_803e7ea4;
  if (((*(byte *)(param_2 + 0x3f0) >> 5 & 1) != 0) ||
     (*(float *)(param_2 + 0x838) <= FLOAT_803e7ea4)) {
    if (*(short *)(param_3 + 0x19c) < 1) {
      *(float *)(param_2 + 0x840) = FLOAT_803e7ee0;
    }
    else {
      *(float *)(param_2 + 0x840) =
           (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x19c) ^ 0x80000000) -
                  DOUBLE_803e7ec0) / FLOAT_803e7ee8;
      fVar2 = *(float *)(param_2 + 0x840);
      fVar4 = FLOAT_803e7ea4;
      if ((FLOAT_803e7ea4 <= fVar2) && (fVar4 = fVar2, FLOAT_803e7ee0 < fVar2)) {
        fVar4 = FLOAT_803e7ee0;
      }
      *(float *)(param_2 + 0x840) = fVar4;
      *(float *)(param_2 + 0x840) = -(FLOAT_803e7eac * *(float *)(param_2 + 0x840) - FLOAT_803e7ee0)
      ;
    }
  }
  else {
    *(float *)(param_2 + 0x840) = (*(float *)(param_2 + 0x838) - FLOAT_803e7ffc) / FLOAT_803e8098;
    fVar1 = *(float *)(param_2 + 0x840);
    if ((fVar2 <= fVar1) && (fVar2 = fVar1, fVar4 < fVar1)) {
      fVar2 = fVar4;
    }
    *(float *)(param_2 + 0x840) = fVar2;
    *(float *)(param_2 + 0x840) = -(FLOAT_803e7e98 * *(float *)(param_2 + 0x840) - FLOAT_803e7ee0);
  }
  if (*(int *)(param_2 + 0x7f8) != 0) {
    *(float *)(param_2 + 0x840) = *(float *)(param_2 + 0x840) - FLOAT_803e7efc;
  }
  fVar2 = *(float *)(param_2 + 0x840);
  fVar4 = FLOAT_803e7e98;
  if ((FLOAT_803e7e98 <= fVar2) && (fVar4 = fVar2, FLOAT_803e7ee0 < fVar2)) {
    fVar4 = FLOAT_803e7ee0;
  }
  *(float *)(param_2 + 0x840) = fVar4;
  *(uint *)(param_2 + 0x360) = *(uint *)(param_2 + 0x360) & 0xfe7fffff;
  __psq_l0(auStack8,uVar10);
  __psq_l1(auStack8,uVar10);
  __psq_l0(auStack24,uVar10);
  __psq_l1(auStack24,uVar10);
  return;
}

