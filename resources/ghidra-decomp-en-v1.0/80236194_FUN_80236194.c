// Function: FUN_80236194
// Entry: 80236194
// Size: 260 bytes

void FUN_80236194(short *param_1,int param_2)

{
  param_1[2] = (ushort)*(byte *)(param_2 + 0x18) << 8;
  param_1[1] = (ushort)*(byte *)(param_2 + 0x19) << 8;
  *param_1 = (ushort)*(byte *)(param_2 + 0x1a) << 8;
  if (*(byte *)(param_2 + 0x1b) != 0) {
    *(float *)(param_1 + 4) =
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x1b)) - DOUBLE_803e7348) /
         FLOAT_803e7338;
    if (*(float *)(param_1 + 4) == FLOAT_803e733c) {
      *(float *)(param_1 + 4) = FLOAT_803e7340;
    }
    FUN_80035974(param_1,(int)((float)((double)CONCAT44(0x43300000,
                                                        (int)*(short *)(*(int *)(param_1 + 0x2a) +
                                                                       0x5a) ^ 0x80000000) -
                                      DOUBLE_803e7350) * *(float *)(param_1 + 4)));
    *(float *)(param_1 + 4) = *(float *)(param_1 + 4) * *(float *)(*(int *)(param_1 + 0x28) + 4);
  }
  param_1[0x58] = param_1[0x58] | 0x4000;
  return;
}

