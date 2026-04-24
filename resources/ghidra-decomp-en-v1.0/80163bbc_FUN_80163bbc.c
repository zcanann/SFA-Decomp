// Function: FUN_80163bbc
// Entry: 80163bbc
// Size: 976 bytes

/* WARNING: Removing unreachable block (ram,0x80163f6c) */

void FUN_80163bbc(short *param_1,int param_2)

{
  int iVar1;
  uint uVar2;
  float **ppfVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  double dVar7;
  undefined8 in_f31;
  double dVar8;
  float **local_68 [2];
  undefined4 local_60;
  uint uStack92;
  undefined4 local_58;
  uint uStack84;
  longlong local_50;
  undefined4 local_48;
  uint uStack68;
  undefined4 local_40;
  uint uStack60;
  longlong local_38;
  undefined4 local_30;
  uint uStack44;
  undefined4 local_28;
  uint uStack36;
  double local_20;
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  local_68[0] = (float **)0x0;
  dVar8 = (double)FLOAT_803e2f78;
  iVar1 = FUN_80065e50((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8),
                       (double)*(float *)(param_1 + 10),param_1,local_68,0,0);
  iVar4 = 0;
  iVar5 = 0;
  ppfVar3 = local_68[0];
  if (0 < iVar1) {
    do {
      dVar7 = (double)(*(float *)(param_1 + 8) - **ppfVar3);
      if (dVar7 < (double)FLOAT_803e2f68) {
        dVar7 = (double)(float)((double)FLOAT_803e2f7c * dVar7 + (double)FLOAT_803e2f5c);
      }
      if (dVar7 < dVar8) {
        iVar5 = iVar4;
        dVar8 = dVar7;
      }
      ppfVar3 = ppfVar3 + 1;
      iVar4 = iVar4 + 1;
      iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
  }
  if (*(float *)(param_1 + 0x12) <= FLOAT_803e2f80) {
    if (*(float *)(param_1 + 0x12) < FLOAT_803e2f7c) {
      *(float *)(param_1 + 0x12) = FLOAT_803e2f7c;
    }
  }
  else {
    *(float *)(param_1 + 0x12) = FLOAT_803e2f80;
  }
  if (*(float *)(param_1 + 0x14) <= FLOAT_803e2f80) {
    if (*(float *)(param_1 + 0x14) < FLOAT_803e2f7c) {
      *(float *)(param_1 + 0x14) = FLOAT_803e2f7c;
    }
  }
  else {
    *(float *)(param_1 + 0x14) = FLOAT_803e2f80;
  }
  if (*(float *)(param_1 + 0x16) <= FLOAT_803e2f80) {
    if (*(float *)(param_1 + 0x16) < FLOAT_803e2f7c) {
      *(float *)(param_1 + 0x16) = FLOAT_803e2f7c;
    }
  }
  else {
    *(float *)(param_1 + 0x16) = FLOAT_803e2f80;
  }
  *(float *)(param_1 + 6) = *(float *)(param_1 + 0x12) * FLOAT_803db414 + *(float *)(param_1 + 6);
  *(float *)(param_1 + 8) = *(float *)(param_1 + 0x14) * FLOAT_803db414 + *(float *)(param_1 + 8);
  *(float *)(param_1 + 10) = *(float *)(param_1 + 0x16) * FLOAT_803db414 + *(float *)(param_1 + 10);
  dVar8 = DOUBLE_803e2f70;
  uStack92 = (int)*(short *)(param_2 + 0x27c) ^ 0x80000000;
  local_60 = 0x43300000;
  uStack84 = (int)param_1[2] ^ 0x80000000;
  local_58 = 0x43300000;
  iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e2f70) * FLOAT_803db414 +
               (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803e2f70));
  local_50 = (longlong)iVar1;
  param_1[2] = (short)iVar1;
  uStack68 = (int)*(short *)(param_2 + 0x27e) ^ 0x80000000;
  local_48 = 0x43300000;
  uStack60 = (int)param_1[1] ^ 0x80000000;
  local_40 = 0x43300000;
  iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack68) - dVar8) * FLOAT_803db414 +
               (float)((double)CONCAT44(0x43300000,uStack60) - dVar8));
  local_38 = (longlong)iVar1;
  param_1[1] = (short)iVar1;
  uStack44 = (int)*(short *)(param_2 + 0x280) ^ 0x80000000;
  local_30 = 0x43300000;
  uStack36 = (int)*param_1 ^ 0x80000000;
  local_28 = 0x43300000;
  iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack44) - dVar8) * FLOAT_803db414 +
               (float)((double)CONCAT44(0x43300000,uStack36) - dVar8));
  local_20 = (double)(longlong)iVar1;
  *param_1 = (short)iVar1;
  if (local_68[0] != (float **)0x0) {
    if (*(float *)(param_1 + 8) <= FLOAT_803e2f60 + *local_68[0][iVar5]) {
      *(float *)(param_1 + 8) = FLOAT_803e2f60 + *local_68[0][iVar5];
      if (param_1[0x23] == 0x3fb) {
        uVar2 = FUN_800221a0(0x8c,0xb4);
        local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        uStack36 = (uint)*(ushort *)(param_2 + 0x268);
        *(float *)(param_1 + 0x14) =
             -(FLOAT_803e2f84 * *(float *)(param_1 + 0x14) *
              ((float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e2f90) /
              (float)(local_20 - DOUBLE_803e2f70)));
      }
      else {
        uVar2 = FUN_800221a0(0x14,0x28);
        local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        uStack36 = (uint)*(ushort *)(param_2 + 0x268);
        *(float *)(param_1 + 0x14) =
             -(FLOAT_803e2f84 * *(float *)(param_1 + 0x14) *
              ((float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e2f90) /
              (float)(local_20 - DOUBLE_803e2f70)));
      }
      local_28 = 0x43300000;
      iVar5 = (int)(FLOAT_803e2f88 * *(float *)(param_1 + 0x14));
      local_20 = (double)(longlong)iVar5;
      if (0x7f < iVar5) {
        iVar5 = 0x7f;
      }
      if (0x10 < iVar5) {
        FUN_8000bb18(param_1,0x27e);
        iVar5 = FUN_800221a0(0,5);
        if ((iVar5 == 0) && ((*(byte *)(param_2 + 0x27a) & 8) != 0)) {
          FUN_8000bb18(param_1,0x27f);
        }
      }
    }
    else {
      *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) + FLOAT_803e2f64;
    }
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  return;
}

