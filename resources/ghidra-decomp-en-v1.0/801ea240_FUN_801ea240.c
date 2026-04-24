// Function: FUN_801ea240
// Entry: 801ea240
// Size: 1080 bytes

/* WARNING: Removing unreachable block (ram,0x801ea650) */

void FUN_801ea240(double param_1,int param_2,int param_3,uint param_4,undefined4 param_5,
                 uint param_6)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  undefined4 uVar5;
  double dVar6;
  undefined8 in_f31;
  double dVar7;
  undefined auStack72 [8];
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  double local_30;
  double local_28;
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  dVar7 = (double)FLOAT_803e5ae8;
  if ((dVar7 <= param_1) && (dVar7 = param_1, (double)FLOAT_803e5b08 < param_1)) {
    dVar7 = (double)FLOAT_803e5b08;
  }
  if (((param_6 & 1) != 0) && (iVar3 = FUN_8000b578(param_2,8), iVar3 != 0)) {
    FLOAT_803ddc64 = (float)((double)FLOAT_803e5b0c * dVar7);
    if (FLOAT_803ddc64 < FLOAT_803e5ae8) {
      FLOAT_803ddc64 = -FLOAT_803ddc64;
    }
    if (FLOAT_803ddc64 < FLOAT_803e5b10) {
      FLOAT_803ddc64 = FLOAT_803e5b10;
    }
    if (FLOAT_803e5b14 < FLOAT_803ddc64) {
      FLOAT_803ddc64 = FLOAT_803e5b14;
    }
    if (FLOAT_803e5b18 <= *(float *)(param_3 + 0x424)) {
      uVar2 = 0;
    }
    else {
      uVar2 = (uint)((double)FLOAT_803e5b1c * dVar7);
      local_30 = (double)(longlong)(int)uVar2;
      if ((int)uVar2 < 0) {
        uVar2 = -uVar2;
      }
      if (0x7f < (int)uVar2) {
        uVar2 = 0x7f;
      }
    }
    FUN_8000b888((double)(FLOAT_803e5b20 + FLOAT_803ddc64 / FLOAT_803e5b08),param_2,8,uVar2 & 0xff);
  }
  if ((((param_6 & 2) != 0) && (iVar3 = FUN_8000b578(param_2,1), iVar3 != 0)) &&
     (*(float *)(param_3 + 0x424) < FLOAT_803e5b18)) {
    dVar6 = (double)FLOAT_803e5ae8;
    if (dVar6 != dVar7) {
      local_30 = (double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 4) ^ 0x80000000);
      dVar6 = (double)((float)(dVar7 * (double)(float)(local_30 - DOUBLE_803e5b00)) / FLOAT_803e5b24
                      );
    }
    FLOAT_803ddc64 = (float)dVar6;
    fVar1 = (float)dVar6;
    if (FLOAT_803e5ae8 <= fVar1) {
      if (FLOAT_803e5aec < fVar1) {
        FLOAT_803ddc64 = FLOAT_803e5aec;
      }
    }
    else {
      FLOAT_803ddc64 = -fVar1;
    }
    uVar2 = (uint)(FLOAT_803e5b28 * FLOAT_803ddc64);
    local_30 = (double)(longlong)(int)uVar2;
    uVar4 = uVar2 ^ 0x80000000;
    local_28 = (double)CONCAT44(0x43300000,uVar4);
    if ((float)(local_28 - DOUBLE_803e5b00) <= FLOAT_803e5b28) {
      local_28 = (double)CONCAT44(0x43300000,uVar4);
      if ((float)(local_28 - DOUBLE_803e5b00) < FLOAT_803e5ae8) {
        uVar2 = 0;
      }
    }
    else {
      uVar2 = 0x7f;
    }
    local_28 = (double)CONCAT44(0x43300000,uVar4);
    FUN_8000b888((double)(FLOAT_803e5b20 + FLOAT_803ddc64),param_2,1,uVar2 & 0xff);
  }
  if ((param_6 & 4) != 0) {
    FUN_8000bb18(param_2,*(undefined2 *)(param_3 + 0x440));
    FUN_8000bb18(param_2,0x11b);
    if ((int)param_4 < 6) {
      if (FLOAT_803e5b10 < *(float *)(param_3 + 0x3f8)) {
        *(float *)(param_3 + 0x3f8) =
             -(FLOAT_803e5b2c * FLOAT_803db414 - *(float *)(param_3 + 0x3f8));
      }
    }
    else {
      *(float *)(param_3 + 0x3f8) = *(float *)(param_3 + 0x3f8) + FLOAT_803db414;
    }
    if (FLOAT_803e5b08 < *(float *)(param_3 + 0x3f8)) {
      *(float *)(param_3 + 0x3f8) = FLOAT_803e5b08;
    }
    if (*(float *)(param_3 + 0x3f8) < FLOAT_803e5b30) {
      *(float *)(param_3 + 0x3f8) = FLOAT_803e5b30;
    }
    iVar3 = (int)*(float *)(param_3 + 0x3f8);
    local_28 = (double)(longlong)iVar3;
    FUN_8000b888((double)(*(float *)(param_3 + 0x3f8) * FLOAT_803e5b38 + FLOAT_803e5b34),param_2,2,
                 iVar3);
    if ((int)param_4 < 6) {
      if (FLOAT_803e5b3c < *(float *)(param_3 + 0x3f4)) {
        *(float *)(param_3 + 0x3f4) =
             -(FLOAT_803e5af8 * FLOAT_803db414 - *(float *)(param_3 + 0x3f4));
      }
    }
    else {
      local_28 = (double)CONCAT44(0x43300000,param_4 ^ 0x80000000);
      *(float *)(param_3 + 0x3f4) = FLOAT_803e5b3c + (float)(local_28 - DOUBLE_803e5b00);
    }
    if (FLOAT_803e5b40 < *(float *)(param_3 + 0x3f4)) {
      *(float *)(param_3 + 0x3f4) = FLOAT_803e5b40;
    }
    if (*(float *)(param_3 + 0x3f4) < FLOAT_803e5b44) {
      *(float *)(param_3 + 0x3f4) = FLOAT_803e5b44;
    }
    iVar3 = (int)*(float *)(param_3 + 0x3f4);
    local_28 = (double)(longlong)iVar3;
    FUN_8000b888((double)(*(float *)(param_3 + 0x3f4) / FLOAT_803e5b48),param_2,4,iVar3);
    local_3c = FLOAT_803e5b4c;
    local_38 = FLOAT_803e5b50;
    local_34 = FLOAT_803e5b54;
    local_40 = FLOAT_803e5ae8;
    FUN_8009837c((double)FLOAT_803e5af8,(double)(*(float *)(param_3 + 0x3f4) / FLOAT_803e5b58),
                 param_2,2,0,1,auStack72);
    local_3c = FLOAT_803e5b5c;
    FUN_8009837c((double)FLOAT_803e5af8,(double)(*(float *)(param_3 + 0x3f4) / FLOAT_803e5b58),
                 param_2,2,0,1,auStack72);
  }
  FUN_801e9c00(param_2,param_3);
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  return;
}

