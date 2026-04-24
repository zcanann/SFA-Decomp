// Function: FUN_80198fa4
// Entry: 80198fa4
// Size: 484 bytes

void FUN_80198fa4(short *param_1,int param_2)

{
  int iVar1;
  float local_c8;
  float local_c4;
  float local_c0;
  short local_bc;
  short local_ba;
  short local_b8;
  float local_b4;
  float local_b0;
  float local_ac;
  float local_a8;
  undefined auStack164 [68];
  undefined auStack96 [64];
  undefined4 local_20;
  uint uStack28;
  
  iVar1 = *(int *)(param_1 + 0x5c);
  *param_1 = (short)((*(byte *)(param_2 + 0x3d) & 0x3f) << 10);
  param_1[1] = (ushort)*(byte *)(param_2 + 0x3e) << 8;
  uStack28 = (uint)*(byte *)(param_2 + 0x3a);
  local_20 = 0x43300000;
  *(float *)(param_1 + 4) =
       *(float *)(*(int *)(param_1 + 0x28) + 4) *
       (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e40f0) * FLOAT_803e40dc;
  local_bc = *param_1;
  local_ba = param_1[1];
  local_b8 = param_1[2];
  local_b4 = FLOAT_803e40e0;
  local_b0 = FLOAT_803e40d8;
  local_ac = FLOAT_803e40d8;
  local_a8 = FLOAT_803e40d8;
  FUN_80021ee8(auStack164,&local_bc);
  FUN_800226cc((double)FLOAT_803e40d8,(double)FLOAT_803e40d8,(double)FLOAT_803e40e0,auStack164,
               &local_c0,&local_c4,&local_c8);
  *(float *)(iVar1 + 0xc) = local_c0;
  *(float *)(iVar1 + 0x10) = local_c4;
  *(float *)(iVar1 + 0x14) = local_c8;
  *(float *)(iVar1 + 0x18) =
       -(*(float *)(param_1 + 0x10) * local_c8 +
        *(float *)(param_1 + 0xc) * local_c0 + *(float *)(param_1 + 0xe) * local_c4);
  local_bc = -*param_1;
  local_ba = -param_1[1];
  local_b8 = 0;
  local_b4 = FLOAT_803e40e0;
  local_b0 = -*(float *)(param_1 + 0xc);
  local_ac = -*(float *)(param_1 + 0xe);
  local_a8 = -*(float *)(param_1 + 0x10);
  FUN_80021ba0(auStack96,&local_bc);
  FUN_80021608(auStack96,iVar1 + 0x38);
  *(float *)(iVar1 + 0x34) = FLOAT_803e40e4 * *(float *)(param_1 + 4);
  *(float *)(iVar1 + 4) =
       FLOAT_803e40e8 * *(float *)(param_1 + 4) * FLOAT_803e40e8 * *(float *)(param_1 + 4);
  if (*(int *)(param_2 + 0x14) == 0x46a31) {
    FUN_8007d6dc(s_initialise_8032253c);
  }
  return;
}

