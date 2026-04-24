// Function: FUN_802b1604
// Entry: 802b1604
// Size: 2584 bytes

/* WARNING: Removing unreachable block (ram,0x802b1ff4) */
/* WARNING: Removing unreachable block (ram,0x802b1fec) */
/* WARNING: Removing unreachable block (ram,0x802b161c) */
/* WARNING: Removing unreachable block (ram,0x802b1614) */

void FUN_802b1604(short *param_1,int param_2,int param_3)

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
  double dVar10;
  double dVar11;
  undefined8 local_78;
  undefined8 local_70;
  
  if ((*(uint *)(param_2 + 0x360) & 0x800000) != 0) {
    sVar3 = *param_1;
    *(short *)(param_2 + 0x484) = sVar3;
    *(short *)(param_2 + 0x478) = sVar3;
    *(int *)(param_2 + 0x494) = (int)sVar3;
    *(float *)(param_3 + 0x298) = FLOAT_803e8b3c;
  }
  *(undefined4 *)(param_3 + 0x29c) = *(undefined4 *)(param_3 + 0x298);
  *(undefined2 *)(param_2 + 0x490) = *(undefined2 *)(param_2 + 0x484);
  *(undefined2 *)(param_2 + 0x492) = *(undefined2 *)(param_2 + 0x478);
  dVar10 = FUN_80293900((double)(*(float *)(param_3 + 0x290) * *(float *)(param_3 + 0x290) +
                                *(float *)(param_3 + 0x28c) * *(float *)(param_3 + 0x28c)));
  *(float *)(param_3 + 0x298) = (float)dVar10;
  if (FLOAT_803e8c40 < *(float *)(param_3 + 0x298)) {
    *(float *)(param_3 + 0x298) = FLOAT_803e8c40;
  }
  *(float *)(param_3 + 0x298) = *(float *)(param_3 + 0x298) / FLOAT_803e8c40;
  *(float *)(param_2 + 0x470) = *(float *)(param_3 + 0x298) - *(float *)(param_3 + 0x29c);
  if (FLOAT_803e8c04 <= *(float *)(param_3 + 0x298)) {
    uVar7 = FUN_80021884();
    *(uint *)(param_2 + 0x474) = uVar7 & 0xffff;
    *(int *)(param_2 + 0x474) = *(int *)(param_2 + 0x474) - (int)*(short *)(param_3 + 0x330);
    if ((*(uint *)(param_2 + 0x360) & 0x1000000) == 0) {
      *(undefined4 *)(param_2 + 0x494) = *(undefined4 *)(param_2 + 0x474);
    }
  }
  else {
    *(float *)(param_3 + 0x298) = FLOAT_803e8b3c;
    *(undefined4 *)(param_2 + 0x474) = *(undefined4 *)(param_2 + 0x494);
  }
  dVar10 = DOUBLE_803e8b58;
  uVar7 = *(int *)(param_2 + 0x474) - (uint)*(ushort *)(param_2 + 0x484);
  if (0x8000 < (int)uVar7) {
    uVar7 = uVar7 - 0xffff;
  }
  if ((int)uVar7 < -0x8000) {
    uVar7 = uVar7 + 0xffff;
  }
  local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
  *(int *)(param_2 + 0x48c) = (int)((float)(local_78 - DOUBLE_803e8b58) / FLOAT_803e8b98);
  if (*(float *)(param_2 + 0x85c) != FLOAT_803e8b3c) {
    fVar2 = *(float *)(param_2 + 0x85c) * *(float *)(param_3 + 0x280);
    uVar5 = *(uint *)(param_2 + 0x48c) ^ 0x80000000;
    local_70 = (double)CONCAT44(0x43300000,uVar5);
    if (((float)(local_70 - dVar10) < fVar2) &&
       (local_70 = (double)CONCAT44(0x43300000,uVar5), -fVar2 < (float)(local_70 - dVar10))) {
      *(undefined4 *)(param_2 + 0x48c) = 0;
    }
  }
  if ((int)uVar7 < 0) {
    *(int *)(param_2 + 0x488) = -*(int *)(param_2 + 0x48c);
  }
  else {
    *(undefined4 *)(param_2 + 0x488) = *(undefined4 *)(param_2 + 0x48c);
  }
  if (FLOAT_803e8c04 <= *(float *)(param_3 + 0x298)) {
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
  dVar10 = DOUBLE_803e8b58;
  uVar7 = *(int *)(param_2 + 0x474) - (uint)*(ushort *)(param_2 + 0x478);
  if (0x8000 < (int)uVar7) {
    uVar7 = uVar7 - 0xffff;
  }
  if ((int)uVar7 < -0x8000) {
    uVar7 = uVar7 + 0xffff;
  }
  local_70 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
  *(int *)(param_2 + 0x480) = (int)((float)(local_70 - DOUBLE_803e8b58) / FLOAT_803e8b98);
  if (*(float *)(param_2 + 0x85c) != FLOAT_803e8b3c) {
    fVar2 = *(float *)(param_2 + 0x85c) * *(float *)(param_3 + 0x280);
    uVar5 = *(uint *)(param_2 + 0x480) ^ 0x80000000;
    local_70 = (double)CONCAT44(0x43300000,uVar5);
    if (((float)(local_70 - dVar10) < fVar2) &&
       (local_70 = (double)CONCAT44(0x43300000,uVar5), -fVar2 < (float)(local_70 - dVar10))) {
      *(undefined4 *)(param_2 + 0x480) = 0;
    }
  }
  if ((int)uVar7 < 0) {
    *(int *)(param_2 + 0x47c) = -*(int *)(param_2 + 0x480);
  }
  else {
    *(undefined4 *)(param_2 + 0x47c) = *(undefined4 *)(param_2 + 0x480);
  }
  uVar7 = *(int *)(param_2 + 0x474) - (uint)*(ushort *)(param_2 + 0x4d4);
  if (0x8000 < (int)uVar7) {
    uVar7 = uVar7 - 0xffff;
  }
  if ((int)uVar7 < -0x8000) {
    uVar7 = uVar7 + 0xffff;
  }
  local_70 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
  *(int *)(param_2 + 0x49c) = (int)((float)(local_70 - DOUBLE_803e8b58) / FLOAT_803e8b98);
  if ((int)uVar7 < 0) {
    *(int *)(param_2 + 0x498) = -*(int *)(param_2 + 0x49c);
  }
  else {
    *(undefined4 *)(param_2 + 0x498) = *(undefined4 *)(param_2 + 0x49c);
  }
  uVar6 = (**(code **)(*DAT_803dd6d0 + 0x40))();
  *(undefined4 *)(param_2 + 0x4b8) = uVar6;
  iVar9 = *(int *)(param_2 + 0x4b8);
  if (iVar9 != 0) {
    dVar11 = (double)(*(float *)(iVar9 + 0xc) - *(float *)(param_1 + 6));
    dVar10 = (double)(*(float *)(iVar9 + 0x14) - *(float *)(param_1 + 10));
    uVar7 = FUN_80021884();
    *(uint *)(param_2 + 0x4ac) = uVar7 & 0xffff;
    dVar10 = FUN_80293900((double)(float)(dVar11 * dVar11 + (double)(float)(dVar10 * dVar10)));
    *(float *)(param_2 + 0x4b0) = (float)dVar10;
    *(ushort *)(param_2 + 0x4b4) = *(byte *)(*(int *)(*(int *)(iVar9 + 0x50) + 0x40) + 0x10) & 0xf;
  }
  uVar7 = *(int *)(param_2 + 0x4ac) - (uint)*(ushort *)(param_2 + 0x478);
  if (0x8000 < (int)uVar7) {
    uVar7 = uVar7 - 0xffff;
  }
  if ((int)uVar7 < -0x8000) {
    uVar7 = uVar7 + 0xffff;
  }
  local_70 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
  *(int *)(param_2 + 0x4a4) = (int)(local_70 - DOUBLE_803e8b58);
  if ((int)uVar7 < 0) {
    *(int *)(param_2 + 0x4a8) = -*(int *)(param_2 + 0x4a4);
  }
  else {
    *(undefined4 *)(param_2 + 0x4a8) = *(undefined4 *)(param_2 + 0x4a4);
  }
  if ((*(byte *)(param_2 + 0x3f1) >> 5 & 1) == 0) {
    dVar11 = (double)*(float *)(param_3 + 0x280);
    dVar10 = (double)FLOAT_803e8b3c;
    if ((dVar10 <= dVar11) && (dVar10 = dVar11, (double)*(float *)(param_2 + 0x404) < dVar11)) {
      dVar10 = (double)*(float *)(param_2 + 0x404);
    }
    dVar11 = dVar10 * (double)*(float *)(param_2 + 0x7e0);
    uVar7 = (uint)dVar11;
    local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
    dVar11 = FUN_80010c84((double)((float)dVar11 - (float)(local_78 - DOUBLE_803e8b58)),
                          (float *)(*(int *)(param_2 + 0x450) + (uVar7 + 1) * 4),(float *)0x0);
    *(float *)(param_2 + 0x438) = (float)((double)FLOAT_803e8b78 / dVar11);
  }
  else {
    dVar11 = FUN_80293900((double)(*(float *)(param_3 + 0x280) * *(float *)(param_3 + 0x280) +
                                  *(float *)(param_3 + 0x284) * *(float *)(param_3 + 0x284)));
    dVar10 = (double)FLOAT_803e8b3c;
    if ((dVar10 <= dVar11) && (dVar10 = dVar11, (double)*(float *)(param_2 + 0x404) < dVar11)) {
      dVar10 = (double)*(float *)(param_2 + 0x404);
    }
    if (FLOAT_803e8b78 == *(float *)(param_2 + 0x82c)) {
      *(float *)(param_2 + 0x438) = FLOAT_803e8bdc;
    }
    else {
      dVar11 = dVar10 * (double)*(float *)(param_2 + 0x7e0);
      uVar7 = (uint)dVar11;
      local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
      dVar11 = FUN_80010c84((double)((float)dVar11 - (float)(local_78 - DOUBLE_803e8b58)),
                            (float *)(*(int *)(param_2 + 0x450) + (uVar7 + 1) * 4),(float *)0x0);
      *(float *)(param_2 + 0x438) = (float)((double)FLOAT_803e8b78 / dVar11);
    }
  }
  dVar11 = dVar10 * (double)*(float *)(param_2 + 0x7e0);
  uVar7 = (uint)dVar11;
  local_78 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
  dVar11 = FUN_80010c84((double)((float)dVar11 - (float)(local_78 - DOUBLE_803e8b58)),
                        (float *)(*(int *)(param_2 + 0x454) + (uVar7 + 1) * 4),(float *)0x0);
  *(float *)(param_2 + 0x428) = (float)dVar11;
  dVar11 = dVar10 * (double)*(float *)(param_2 + 0x7e0);
  uVar7 = (uint)dVar11;
  dVar11 = FUN_80010c84((double)((float)dVar11 -
                                (float)((double)CONCAT44(0x43300000,uVar7 ^ 0x80000000) -
                                       DOUBLE_803e8b58)),
                        (float *)(*(int *)(param_2 + 0x458) + (uVar7 + 1) * 4),(float *)0x0);
  *(float *)(param_2 + 0x42c) = (float)dVar11;
  dVar11 = dVar10 * (double)*(float *)(param_2 + 0x7e0);
  uVar7 = (uint)dVar11;
  dVar11 = FUN_80010c84((double)((float)dVar11 -
                                (float)((double)CONCAT44(0x43300000,uVar7 ^ 0x80000000) -
                                       DOUBLE_803e8b58)),
                        (float *)(*(int *)(param_2 + 0x45c) + (uVar7 + 1) * 4),(float *)0x0);
  *(float *)(param_2 + 0x430) = (float)dVar11;
  dVar10 = dVar10 * (double)*(float *)(param_2 + 0x7e0);
  uVar7 = (uint)dVar10;
  dVar10 = FUN_80010c84((double)((float)dVar10 -
                                (float)((double)CONCAT44(0x43300000,uVar7 ^ 0x80000000) -
                                       DOUBLE_803e8b58)),
                        (float *)(*(int *)(param_2 + 0x460) + (uVar7 + 1) * 4),(float *)0x0);
  *(float *)(param_2 + 0x434) = (float)dVar10;
  fVar2 = FLOAT_803e8d7c;
  if ((*(byte *)(param_2 + 0x3f0) >> 5 & 1) == 0) {
    if (FLOAT_803e8b78 != *(float *)(param_2 + 0x834)) {
      fVar2 = *(float *)(*(int *)(param_2 + 0x400) + 0x10);
      fVar4 = (*(float *)(param_3 + 0x280) - fVar2) / (*(float *)(param_2 + 0x404) - fVar2);
      fVar2 = FLOAT_803e8b3c;
      if ((FLOAT_803e8b3c <= fVar4) && (fVar2 = fVar4, FLOAT_803e8b78 < fVar4)) {
        fVar2 = FLOAT_803e8b78;
      }
      *(float *)(param_2 + 0x430) =
           *(float *)(param_2 + 0x430) *
           ((*(float *)(param_2 + 0x834) - FLOAT_803e8b78) * fVar2 + FLOAT_803e8b78);
    }
  }
  else {
    *(float *)(param_2 + 0x428) = *(float *)(param_2 + 0x428) * FLOAT_803e8d7c;
    *(float *)(param_2 + 0x430) = *(float *)(param_2 + 0x430) * fVar2;
    *(float *)(param_2 + 0x438) = *(float *)(param_2 + 0x438) * FLOAT_803e8bdc;
  }
  if (*(int *)(param_2 + 0x464) == 0) {
    *(float *)(param_2 + 0x420) = FLOAT_803e8b78;
  }
  else {
    iVar8 = *(int *)(param_2 + 0x47c);
    iVar9 = iVar8 / 5 + (iVar8 >> 0x1f);
    dVar10 = FUN_80010c84((double)((float)((double)CONCAT44(0x43300000,
                                                            iVar8 + (iVar9 - (iVar9 >> 0x1f)) * -5 ^
                                                            0x80000000) - DOUBLE_803e8b58) /
                                  FLOAT_803e8ba8),
                          (float *)(*(int *)(param_2 + 0x464) + ((iVar9 - (iVar9 >> 0x1f)) + 1) * 4)
                          ,(float *)0x0);
    *(float *)(param_2 + 0x420) = (float)dVar10;
  }
  fVar4 = FLOAT_803e8b78;
  *(float *)(param_2 + 0x420) = FLOAT_803e8b78;
  fVar2 = FLOAT_803e8b3c;
  if (((*(byte *)(param_2 + 0x3f0) >> 5 & 1) != 0) ||
     (*(float *)(param_2 + 0x838) <= FLOAT_803e8b3c)) {
    if (*(short *)(param_3 + 0x19c) < 1) {
      *(float *)(param_2 + 0x840) = FLOAT_803e8b78;
    }
    else {
      *(float *)(param_2 + 0x840) =
           (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x19c) ^ 0x80000000) -
                  DOUBLE_803e8b58) / FLOAT_803e8b80;
      fVar2 = *(float *)(param_2 + 0x840);
      fVar4 = FLOAT_803e8b3c;
      if ((FLOAT_803e8b3c <= fVar2) && (fVar4 = fVar2, FLOAT_803e8b78 < fVar2)) {
        fVar4 = FLOAT_803e8b78;
      }
      *(float *)(param_2 + 0x840) = fVar4;
      *(float *)(param_2 + 0x840) = -(FLOAT_803e8b44 * *(float *)(param_2 + 0x840) - FLOAT_803e8b78)
      ;
    }
  }
  else {
    *(float *)(param_2 + 0x840) = (*(float *)(param_2 + 0x838) - FLOAT_803e8c94) / FLOAT_803e8d30;
    fVar1 = *(float *)(param_2 + 0x840);
    if ((fVar2 <= fVar1) && (fVar2 = fVar1, fVar4 < fVar1)) {
      fVar2 = fVar4;
    }
    *(float *)(param_2 + 0x840) = fVar2;
    *(float *)(param_2 + 0x840) = -(FLOAT_803e8b30 * *(float *)(param_2 + 0x840) - FLOAT_803e8b78);
  }
  if (*(int *)(param_2 + 0x7f8) != 0) {
    *(float *)(param_2 + 0x840) = *(float *)(param_2 + 0x840) - FLOAT_803e8b94;
  }
  fVar2 = *(float *)(param_2 + 0x840);
  fVar4 = FLOAT_803e8b30;
  if ((FLOAT_803e8b30 <= fVar2) && (fVar4 = fVar2, FLOAT_803e8b78 < fVar2)) {
    fVar4 = FLOAT_803e8b78;
  }
  *(float *)(param_2 + 0x840) = fVar4;
  *(uint *)(param_2 + 0x360) = *(uint *)(param_2 + 0x360) & 0xfe7fffff;
  return;
}

