// Function: FUN_801a4708
// Entry: 801a4708
// Size: 124 bytes

void FUN_801a4708(short *param_1,int param_2)

{
  param_1[0x7a] = 0;
  param_1[0x7b] = 0;
  *param_1 = (ushort)*(byte *)(param_2 + 0x1f) << 8;
  *(code **)(param_1 + 0x5e) = FUN_801a4450;
  *(float *)(param_1 + 4) =
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x21)) - DOUBLE_803e5060) *
       FLOAT_803e5058;
  *(float *)(param_1 + 4) = *(float *)(param_1 + 4) * *(float *)(*(int *)(param_1 + 0x28) + 4);
  **(byte **)(param_1 + 0x5c) = **(byte **)(param_1 + 0x5c) & 0x1f;
  return;
}

