// Function: FUN_802abae8
// Entry: 802abae8
// Size: 1236 bytes

/* WARNING: Removing unreachable block (ram,0x802abf98) */

void FUN_802abae8(double param_1,int param_2,int param_3,int param_4)

{
  float fVar1;
  byte bVar2;
  float fVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  undefined4 uVar7;
  double dVar8;
  undefined8 in_f31;
  double local_58;
  double local_50;
  double local_40;
  double local_38;
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar5 = (int)*(short *)(param_4 + 0x478) - ((int)*(short *)(param_4 + 0x492) & 0xffffU);
  if (0x8000 < (int)uVar5) {
    uVar5 = uVar5 - 0xffff;
  }
  if ((int)uVar5 < -0x8000) {
    uVar5 = uVar5 + 0xffff;
  }
  if (((*(byte *)(param_4 + 0x3f1) >> 5 & 1) != 0) || ((*(byte *)(param_4 + 0x3f0) >> 4 & 1) != 0))
  {
    uVar5 = 0;
  }
  fVar1 = FLOAT_803e7e98 * (*(float *)(param_3 + 0x294) - FLOAT_803e7e9c) + FLOAT_803e7ee0;
  if (fVar1 < FLOAT_803e7ea4) {
    fVar1 = FLOAT_803e7ea4;
  }
  local_58 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
  iVar6 = (int)((float)(local_58 - DOUBLE_803e7ec0) * FLOAT_803e7fc4 * fVar1);
  if (iVar6 < -0xccc) {
    iVar6 = -0xccc;
  }
  else if (0xccc < iVar6) {
    iVar6 = 0xccc;
  }
  uVar5 = iVar6 - ((int)*(short *)(param_4 + 0x4d0) & 0xffffU);
  if (0x8000 < (int)uVar5) {
    uVar5 = uVar5 - 0xffff;
  }
  if ((int)uVar5 < -0x8000) {
    uVar5 = uVar5 + 0xffff;
  }
  dVar8 = (double)FUN_80021370((double)(float)((double)CONCAT44(0x43300000,uVar5 ^ 0x80000000) -
                                              DOUBLE_803e7ec0),(double)FLOAT_803e7eb4,
                               (double)FLOAT_803db414);
  local_40 = (double)CONCAT44(0x43300000,(int)*(short *)(param_4 + 0x4d0) ^ 0x80000000);
  *(short *)(param_4 + 0x4d0) = (short)(int)((double)(float)(local_40 - DOUBLE_803e7ec0) + dVar8);
  iVar6 = FUN_802ab1d0(param_2);
  if ((((iVar6 == 0) || (bVar2 = *(byte *)(param_4 + 0x3f0), (char)bVar2 < '\0')) ||
      ((bVar2 >> 6 & 1) != 0)) || (((bVar2 >> 4 & 1) != 0 || ((bVar2 >> 5 & 1) != 0)))) {
    iVar6 = 0;
  }
  else {
    uVar5 = FUN_800217c0(-(double)(*(float *)(iVar6 + 0xc) - *(float *)(param_2 + 0xc)),
                         -(double)(*(float *)(iVar6 + 0x14) - *(float *)(param_2 + 0x14)));
    uVar5 = (uVar5 & 0xffff) - ((int)*(short *)(param_4 + 0x478) & 0xffffU);
    if (0x8000 < (int)uVar5) {
      uVar5 = uVar5 - 0xffff;
    }
    if ((int)uVar5 < -0x8000) {
      uVar5 = uVar5 + 0xffff;
    }
    fVar1 = FLOAT_803e7ee0 -
            (*(float *)(param_3 + 0x294) - FLOAT_803e7e9c) /
            (*(float *)(param_4 + 0x404) - FLOAT_803e7e9c);
    fVar3 = FLOAT_803e7ea4;
    if ((FLOAT_803e7ea4 <= fVar1) && (fVar3 = fVar1, FLOAT_803e7ee0 < fVar1)) {
      fVar3 = FLOAT_803e7ee0;
    }
    fVar3 = FLOAT_803e80c4 * fVar3 + FLOAT_803e80f4;
    uVar5 = uVar5 ^ 0x80000000;
    local_38 = (double)CONCAT44(0x43300000,uVar5);
    fVar1 = FLOAT_803e80f8 * -fVar3;
    if (fVar1 <= (float)(local_38 - DOUBLE_803e7ec0)) {
      local_38 = (double)CONCAT44(0x43300000,uVar5);
      fVar1 = FLOAT_803e80f8 * fVar3;
      if ((float)(local_38 - DOUBLE_803e7ec0) <= fVar1) {
        local_40 = (double)CONCAT44(0x43300000,uVar5);
        fVar1 = (float)(local_40 - DOUBLE_803e7ec0);
      }
    }
    iVar6 = (int)fVar1;
  }
  if (((*(byte *)(param_4 + 0x3f1) >> 5 & 1) == 0) && ((*(byte *)(param_4 + 0x3f0) >> 4 & 1) == 0))
  {
    iVar4 = *(int *)(param_4 + 0x480);
  }
  else {
    iVar4 = 0;
  }
  if (iVar4 < -0x28) {
    iVar4 = -0x28;
  }
  else if (0x28 < iVar4) {
    iVar4 = 0x28;
  }
  iVar6 = iVar6 + iVar4 * 0xb6;
  if (iVar6 < -0x3ffc) {
    iVar6 = -0x3ffc;
  }
  else if (0x3ffc < iVar6) {
    iVar6 = 0x3ffc;
  }
  uVar5 = iVar6 - ((int)*(short *)(param_4 + 0x4d4) & 0xffffU);
  if (0x8000 < (int)uVar5) {
    uVar5 = uVar5 - 0xffff;
  }
  if ((int)uVar5 < -0x8000) {
    uVar5 = uVar5 + 0xffff;
  }
  local_38 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
  uVar5 = (uint)((float)(local_38 - DOUBLE_803e7ec0) * FLOAT_803e7eb4);
  if ((int)uVar5 < -0x16c) {
    uVar5 = 0xfffffe94;
  }
  else if (0x16c < (int)uVar5) {
    uVar5 = 0x16c;
  }
  local_50 = (double)CONCAT44(0x43300000,(int)*(short *)(param_4 + 0x4d4) ^ 0x80000000);
  *(short *)(param_4 + 0x4d4) =
       (short)(int)((float)((double)CONCAT44(0x43300000,uVar5 ^ 0x80000000) - DOUBLE_803e7ec0) *
                    FLOAT_803db414 + (float)(local_50 - DOUBLE_803e7ec0));
  *(short *)(param_4 + 0x4d2) = *(short *)(param_4 + 0x4d4) / 2;
  iVar6 = (int)(FLOAT_803e80f8 * (float)((double)FLOAT_803e7ed8 * -param_1)) -
          ((int)*(short *)(param_4 + 0x4d6) & 0xffffU);
  if (0x8000 < iVar6) {
    iVar6 = iVar6 + -0xffff;
  }
  if (iVar6 < -0x8000) {
    iVar6 = iVar6 + 0xffff;
  }
  *(short *)(param_4 + 0x4d6) = *(short *)(param_4 + 0x4d6) + (short)iVar6;
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  return;
}

