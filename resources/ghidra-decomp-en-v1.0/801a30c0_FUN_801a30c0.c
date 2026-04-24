// Function: FUN_801a30c0
// Entry: 801a30c0
// Size: 1188 bytes

/* WARNING: Removing unreachable block (ram,0x801a353c) */

void FUN_801a30c0(int param_1,int param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  undefined4 uVar3;
  double dVar4;
  double dVar5;
  undefined8 in_f31;
  float local_58;
  float local_54;
  float local_50 [2];
  undefined4 local_48;
  uint uStack68;
  undefined4 local_40;
  uint uStack60;
  double local_38;
  undefined4 local_30;
  uint uStack44;
  double local_28;
  undefined auStack8 [8];
  
  uVar3 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  FUN_80021ac8(param_3 + 0x1a,param_2 + 0x10);
  *(float *)(param_2 + 0x4c) =
       *(float *)(param_2 + 0x10) * *(float *)(param_1 + 8) + *(float *)(param_3 + 8);
  *(float *)(param_2 + 0x50) =
       *(float *)(param_2 + 0x14) * *(float *)(param_1 + 8) + *(float *)(param_3 + 0xc);
  *(float *)(param_2 + 0x54) =
       *(float *)(param_2 + 0x18) * *(float *)(param_1 + 8) + *(float *)(param_3 + 0x10);
  *(undefined2 *)(param_2 + 0x68) = *(undefined2 *)(param_3 + 0x1a);
  *(undefined2 *)(param_2 + 0x66) = *(undefined2 *)(param_3 + 0x1c);
  *(undefined2 *)(param_2 + 100) = *(undefined2 *)(param_3 + 0x1e);
  uStack68 = (int)*(short *)(param_3 + 0x20) ^ 0x80000000;
  local_48 = 0x43300000;
  local_50[0] = *(float *)(param_2 + 0x10) -
                (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e4388);
  uStack60 = (int)*(short *)(param_3 + 0x22) ^ 0x80000000;
  local_40 = 0x43300000;
  local_54 = *(float *)(param_2 + 0x14) -
             (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e4388);
  local_38 = (double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x24) ^ 0x80000000);
  local_58 = *(float *)(param_2 + 0x18) - (float)(local_38 - DOUBLE_803e4388);
  dVar4 = (double)FUN_802931a0((double)(local_58 * local_58 +
                                       local_50[0] * local_50[0] + local_54 * local_54));
  dVar5 = (double)FLOAT_803e4368;
  if (dVar4 != dVar5) {
    local_38 = (double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x2c) ^ 0x80000000);
    dVar4 = (double)((float)(local_38 - DOUBLE_803e4388) / (float)((double)FLOAT_803e4370 * dVar4));
    if ((((double)local_50[0] != dVar5) || ((double)local_54 != dVar5)) ||
       ((double)local_58 != dVar5)) {
      FUN_800701a4(local_50,&local_54,&local_58);
    }
    *(float *)(param_2 + 0x40) = (float)((double)local_50[0] * dVar4);
    *(float *)(param_2 + 0x44) = (float)((double)local_54 * dVar4);
    *(float *)(param_2 + 0x48) = (float)((double)local_58 * dVar4);
    iVar2 = (int)(FLOAT_803e4374 * (float)((double)FLOAT_803e4378 + dVar4));
    local_38 = (double)(longlong)iVar2;
    uStack60 = FUN_800221a0(0,iVar2);
    uStack60 = uStack60 ^ 0x80000000;
    local_40 = 0x43300000;
    *(float *)(param_2 + 0x1c) =
         (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e4388) / FLOAT_803e437c;
    uStack68 = FUN_800221a0(0,iVar2);
    uStack68 = uStack68 ^ 0x80000000;
    local_48 = 0x43300000;
    *(float *)(param_2 + 0x20) =
         (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e4388) / FLOAT_803e437c;
    uStack44 = FUN_800221a0(0,iVar2);
    dVar4 = DOUBLE_803e4388;
    uStack44 = uStack44 ^ 0x80000000;
    local_30 = 0x43300000;
    *(float *)(param_2 + 0x24) =
         (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e4388) / FLOAT_803e437c;
    local_28 = (double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x30) ^ 0x80000000);
    dVar4 = (double)((float)(local_28 - dVar4) / FLOAT_803e4358);
    if (FLOAT_803e4368 < *(float *)(param_1 + 0x24)) {
      *(byte *)(param_2 + 0x6c) = *(byte *)(param_2 + 0x6c) | 1;
    }
    if (FLOAT_803e4368 < *(float *)(param_1 + 0x2c)) {
      *(byte *)(param_2 + 0x6c) = *(byte *)(param_2 + 0x6c) | 2;
    }
    if (FLOAT_803e4368 < *(float *)(param_2 + 0x1c)) {
      *(byte *)(param_2 + 0x6c) = *(byte *)(param_2 + 0x6c) | 4;
    }
    if (FLOAT_803e4368 < *(float *)(param_2 + 0x20)) {
      *(byte *)(param_2 + 0x6c) = *(byte *)(param_2 + 0x6c) | 8;
    }
    if (FLOAT_803e4368 < *(float *)(param_2 + 0x24)) {
      *(byte *)(param_2 + 0x6c) = *(byte *)(param_2 + 0x6c) | 0x10;
    }
    iVar2 = (int)(FLOAT_803e4374 * (float)((double)FLOAT_803e4378 + dVar4));
    local_28 = (double)(longlong)iVar2;
    uStack44 = FUN_800221a0(0,iVar2);
    uStack44 = uStack44 ^ 0x80000000;
    local_30 = 0x43300000;
    *(float *)(param_2 + 0x28) =
         (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e4388) / FLOAT_803e4374;
    uVar1 = FUN_800221a0(0,iVar2);
    local_38 = (double)CONCAT44(0x43300000,uVar1 ^ 0x80000000);
    *(float *)(param_2 + 0x2c) = (float)(local_38 - DOUBLE_803e4388) / FLOAT_803e4374;
    uStack60 = FUN_800221a0(0,iVar2);
    dVar5 = DOUBLE_803e4388;
    uStack60 = uStack60 ^ 0x80000000;
    local_40 = 0x43300000;
    *(float *)(param_2 + 0x30) =
         (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e4388) / FLOAT_803e4374;
    *(float *)(param_2 + 0x34) = (float)((double)local_50[0] * dVar4);
    *(float *)(param_2 + 0x38) = (float)((double)local_54 * dVar4 - (double)FLOAT_803e4380);
    *(float *)(param_2 + 0x3c) = (float)((double)local_58 * dVar4);
    if ((int)*(short *)(param_3 + 0x2e) != 0) {
      local_28 = (double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x2e) ^ 0x80000000);
      *(float *)(param_2 + 0x58) = (float)(local_28 - dVar5);
    }
    *(uint *)(param_2 + 0x5c) = (uint)*(ushort *)(param_3 + 0x38);
    if (*(short *)(param_3 + 0x38) == 0) {
      *(undefined4 *)(param_2 + 0x60) = 0xffffffff;
    }
    else {
      iVar2 = FUN_800221a0(0,100);
      iVar2 = (uint)*(ushort *)(param_3 + 0x38) * (iVar2 + 100);
      iVar2 = iVar2 / 200 + (iVar2 >> 0x1f);
      *(int *)(param_2 + 0x60) = iVar2 - (iVar2 >> 0x1f);
    }
  }
  __psq_l0(auStack8,uVar3);
  __psq_l1(auStack8,uVar3);
  return;
}

