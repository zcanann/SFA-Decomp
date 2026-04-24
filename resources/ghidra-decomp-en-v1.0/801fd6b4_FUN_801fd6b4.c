// Function: FUN_801fd6b4
// Entry: 801fd6b4
// Size: 852 bytes

/* WARNING: Removing unreachable block (ram,0x801fd9e4) */

void FUN_801fd6b4(int param_1)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  double dVar6;
  undefined8 in_f31;
  double dVar7;
  undefined auStack88 [8];
  undefined4 local_50;
  double local_40;
  double local_38;
  double local_30;
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar4 = *(int *)(param_1 + 0xb8);
  iVar3 = *(int *)(param_1 + 0x4c);
  local_40 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x36));
  dVar6 = local_40 - DOUBLE_803e61a0;
  *(float *)(iVar4 + 0xc) =
       FLOAT_803db414 * ((FLOAT_803e6160 * *(float *)(iVar4 + 0x10)) / FLOAT_803e6160) +
       *(float *)(iVar4 + 0xc);
  fVar1 = (float)dVar6;
  if (FLOAT_803e6164 < *(float *)(iVar4 + 0xc)) {
    uVar2 = FUN_800221a0(0x32,100);
    local_40 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    *(float *)(iVar4 + 0x10) = (float)(local_40 - DOUBLE_803e61a8);
    uVar2 = FUN_800221a0(0x15e,800);
    local_38 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    local_30 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar3 + 0x1a) ^ 0x80000000);
    *(float *)(iVar4 + 8) =
         FLOAT_803e6168 /
         ((float)(local_30 - DOUBLE_803e61a8) / (float)(local_38 - DOUBLE_803e61a8));
    *(float *)(iVar4 + 0xc) = FLOAT_803e616c;
    FUN_8000bb18(param_1,0x111);
    fVar1 = FLOAT_803e6170;
  }
  dVar7 = (double)fVar1;
  local_30 = (double)(longlong)(int)*(float *)(iVar4 + 0xc);
  local_38 = (double)CONCAT44(0x43300000,(int)(short)(int)*(float *)(iVar4 + 0xc) ^ 0x80000000);
  dVar6 = (double)FUN_80293e80((double)((FLOAT_803e6174 * (float)(local_38 - DOUBLE_803e61a8)) /
                                       FLOAT_803e6178));
  FLOAT_803ddcd0 = (float)dVar6;
  *(float *)(param_1 + 8) =
       FLOAT_803e617c * *(float *)(iVar4 + 8) +
       FLOAT_803e6180 * *(float *)(iVar4 + 8) * (float)dVar6;
  if (((FLOAT_803e6184 < *(float *)(iVar4 + 0xc)) && (*(float *)(iVar4 + 0xc) < FLOAT_803e6188)) &&
     (local_50 = *(undefined4 *)(iVar4 + 8), (*(ushort *)(param_1 + 0xb0) & 0x800) != 0)) {
    (**(code **)(*DAT_803dca88 + 8))(param_1,0x3a2,auStack88,2,0xffffffff,0);
  }
  fVar1 = *(float *)(iVar4 + 0xc);
  if (FLOAT_803e618c < fVar1) {
    local_30 = (double)(longlong)(int)(FLOAT_803e6170 * FLOAT_803ddcd0);
    local_38 = (double)CONCAT44(0x43300000,
                                (int)(short)(int)(FLOAT_803e6170 * FLOAT_803ddcd0) ^ 0x80000000);
    dVar7 = (double)(float)(local_38 - DOUBLE_803e61a8);
  }
  if (fVar1 < FLOAT_803e6190) {
    dVar7 = (double)(FLOAT_803e6170 * (fVar1 / FLOAT_803e6190));
  }
  dVar6 = (double)FLOAT_803e616c;
  if ((dVar6 <= dVar7) && (dVar6 = dVar7, (double)FLOAT_803e6170 < dVar7)) {
    dVar6 = (double)FLOAT_803e6170;
  }
  local_40 = (double)(longlong)(int)dVar6;
  *(char *)(param_1 + 0x36) = (char)(int)dVar6;
  iVar3 = FUN_800394ac(param_1,0,0);
  if (iVar3 != 0) {
    local_30 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar3 + 10) ^ 0x80000000);
    fVar1 = (float)(local_30 - DOUBLE_803e61a8) + FLOAT_803e6160;
    if (FLOAT_803e6194 <= fVar1) {
      fVar1 = fVar1 - FLOAT_803e6194;
    }
    local_38 = (double)(longlong)(int)fVar1;
    *(short *)(iVar3 + 10) = (short)(int)fVar1;
  }
  iVar3 = FUN_800394ac(param_1,1,0);
  if (iVar3 != 0) {
    local_30 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar3 + 10) ^ 0x80000000);
    fVar1 = (float)(local_30 - DOUBLE_803e61a8) + FLOAT_803e6198;
    if (FLOAT_803e6194 <= fVar1) {
      fVar1 = fVar1 - FLOAT_803e6194;
    }
    *(short *)(iVar3 + 10) = (short)(int)fVar1;
  }
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  return;
}

