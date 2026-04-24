// Function: FUN_801a5298
// Entry: 801a5298
// Size: 896 bytes

/* WARNING: Removing unreachable block (ram,0x801a55f8) */

int FUN_801a5298(short *param_1,int param_2)

{
  int iVar1;
  float fVar2;
  float fVar3;
  double dVar4;
  undefined4 uVar5;
  undefined8 in_f31;
  double dVar6;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  undefined4 local_50;
  uint uStack76;
  longlong local_48;
  undefined4 local_40;
  uint uStack60;
  longlong local_38;
  undefined4 local_30;
  uint uStack44;
  longlong local_28;
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  dVar6 = (double)FLOAT_803e43f0;
  FUN_8002b1e8(param_1,param_2,&local_68,0);
  *(float *)(param_1 + 0x12) =
       FLOAT_803db414 * *(float *)(param_2 + 0x30) + *(float *)(param_1 + 0x12);
  *(float *)(param_1 + 0x14) =
       FLOAT_803db414 * *(float *)(param_2 + 0x34) + *(float *)(param_1 + 0x14);
  *(float *)(param_1 + 0x16) =
       FLOAT_803db414 * *(float *)(param_2 + 0x38) + *(float *)(param_1 + 0x16);
  *(float *)(param_2 + 0x18) =
       FLOAT_803db414 * *(float *)(param_2 + 0x24) + *(float *)(param_2 + 0x18);
  *(float *)(param_2 + 0x1c) =
       FLOAT_803db414 * *(float *)(param_2 + 0x28) + *(float *)(param_2 + 0x1c);
  *(float *)(param_2 + 0x20) =
       FLOAT_803db414 * *(float *)(param_2 + 0x2c) + *(float *)(param_2 + 0x20);
  fVar3 = FLOAT_803e43f0;
  if (*(float *)(param_2 + 0x54) <= local_64) {
    *(byte *)(param_2 + 0x66) = *(byte *)(param_2 + 0x66) & 0xfb;
  }
  else {
    if (((*(float *)(param_1 + 0x14) < FLOAT_803e43f0) && ((*(byte *)(param_2 + 0x66) & 4) != 0)) ||
       (FLOAT_803e43f0 == *(float *)(param_1 + 0x14))) {
      *(float *)(param_2 + 0x34) = FLOAT_803e43f0;
      *(float *)(param_2 + 0x2c) = fVar3;
      *(float *)(param_2 + 0x20) = fVar3;
      *(float *)(param_2 + 0x28) = fVar3;
      *(float *)(param_2 + 0x1c) = fVar3;
      *(float *)(param_2 + 0x24) = fVar3;
      *(float *)(param_2 + 0x18) = fVar3;
      *(float *)(param_1 + 0x14) = fVar3;
      fVar2 = FLOAT_803e4418;
      *(float *)(param_2 + 0x30) = *(float *)(param_2 + 0x30) * FLOAT_803e4418;
      *(float *)(param_1 + 0x12) = *(float *)(param_1 + 0x12) * fVar2;
      *(float *)(param_2 + 0x38) = *(float *)(param_2 + 0x38) * fVar2;
      *(float *)(param_1 + 0x16) = *(float *)(param_1 + 0x16) * fVar2;
      fVar2 = *(float *)(param_1 + 0x12);
      if (fVar2 < fVar3) {
        fVar2 = -fVar2;
      }
      if (fVar2 < FLOAT_803e441c) {
        fVar3 = *(float *)(param_1 + 0x16);
        if (fVar3 < FLOAT_803e43f0) {
          fVar3 = -fVar3;
        }
        if (fVar3 < FLOAT_803e441c) {
          dVar6 = (double)FLOAT_803e43f4;
        }
      }
    }
    if (*(float *)(param_1 + 0x14) < FLOAT_803e43f0) {
      *(float *)(param_1 + 0x14) = FLOAT_803e4420 * -*(float *)(param_1 + 0x14);
      fVar3 = FLOAT_803e4418;
      *(float *)(param_1 + 0x12) = *(float *)(param_1 + 0x12) * FLOAT_803e4418;
      *(float *)(param_1 + 0x16) = *(float *)(param_1 + 0x16) * fVar3;
      *(float *)(param_2 + 0x34) = FLOAT_803e4424;
      *(float *)(param_2 + 0x2c) = -*(float *)(param_2 + 0x2c);
    }
    *(byte *)(param_2 + 0x66) = *(byte *)(param_2 + 0x66) | 4;
  }
  dVar4 = DOUBLE_803e4410;
  uStack76 = (int)*param_1 ^ 0x80000000;
  local_50 = 0x43300000;
  iVar1 = (int)(*(float *)(param_2 + 0x18) * FLOAT_803db414 +
               (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e4410));
  local_48 = (longlong)iVar1;
  *param_1 = (short)iVar1;
  uStack60 = (int)param_1[1] ^ 0x80000000;
  local_40 = 0x43300000;
  iVar1 = (int)(*(float *)(param_2 + 0x1c) * FLOAT_803db414 +
               (float)((double)CONCAT44(0x43300000,uStack60) - dVar4));
  local_38 = (longlong)iVar1;
  param_1[1] = (short)iVar1;
  uStack44 = (int)param_1[2] ^ 0x80000000;
  local_30 = 0x43300000;
  iVar1 = (int)(*(float *)(param_2 + 0x20) * FLOAT_803db414 +
               (float)((double)CONCAT44(0x43300000,uStack44) - dVar4));
  local_28 = (longlong)iVar1;
  param_1[2] = (short)iVar1;
  FUN_8002b1e8(param_1,param_2,&local_5c,0);
  *(float *)(param_1 + 6) = *(float *)(param_1 + 6) + (local_68 - local_5c);
  *(float *)(param_1 + 8) = *(float *)(param_1 + 8) + (local_64 - local_58);
  *(float *)(param_1 + 10) = *(float *)(param_1 + 10) + (local_60 - local_54);
  *(float *)(param_1 + 6) = *(float *)(param_1 + 0x12) * FLOAT_803db414 + *(float *)(param_1 + 6);
  *(float *)(param_1 + 8) = *(float *)(param_1 + 0x14) * FLOAT_803db414 + *(float *)(param_1 + 8);
  *(float *)(param_1 + 10) = *(float *)(param_1 + 0x16) * FLOAT_803db414 + *(float *)(param_1 + 10);
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  return (int)dVar6;
}

