// Function: FUN_80199520
// Entry: 80199520
// Size: 484 bytes

void FUN_80199520(ushort *param_1,int param_2)

{
  int iVar1;
  float local_c8;
  float local_c4;
  float local_c0;
  ushort local_bc;
  ushort local_ba;
  ushort local_b8;
  float local_b4;
  float local_b0;
  float local_ac;
  float local_a8;
  float afStack_a4 [17];
  float afStack_60 [16];
  undefined4 local_20;
  uint uStack_1c;
  
  iVar1 = *(int *)(param_1 + 0x5c);
  *param_1 = (ushort)((*(byte *)(param_2 + 0x3d) & 0x3f) << 10);
  param_1[1] = (ushort)*(byte *)(param_2 + 0x3e) << 8;
  uStack_1c = (uint)*(byte *)(param_2 + 0x3a);
  local_20 = 0x43300000;
  *(float *)(param_1 + 4) =
       *(float *)(*(int *)(param_1 + 0x28) + 4) *
       (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e4d88) * FLOAT_803e4d74;
  local_bc = *param_1;
  local_ba = param_1[1];
  local_b8 = param_1[2];
  local_b4 = FLOAT_803e4d78;
  local_b0 = FLOAT_803e4d70;
  local_ac = FLOAT_803e4d70;
  local_a8 = FLOAT_803e4d70;
  FUN_80021fac(afStack_a4,&local_bc);
  FUN_80022790((double)FLOAT_803e4d70,(double)FLOAT_803e4d70,(double)FLOAT_803e4d78,afStack_a4,
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
  local_b4 = FLOAT_803e4d78;
  local_b0 = -*(float *)(param_1 + 0xc);
  local_ac = -*(float *)(param_1 + 0xe);
  local_a8 = -*(float *)(param_1 + 0x10);
  FUN_80021c64(afStack_60,(int)&local_bc);
  FUN_800216cc(afStack_60,(undefined4 *)(iVar1 + 0x38));
  *(float *)(iVar1 + 0x34) = FLOAT_803e4d7c * *(float *)(param_1 + 4);
  *(float *)(iVar1 + 4) =
       FLOAT_803e4d80 * *(float *)(param_1 + 4) * FLOAT_803e4d80 * *(float *)(param_1 + 4);
  if (*(int *)(param_2 + 0x14) == 0x46a31) {
    FUN_8007d858();
  }
  return;
}

