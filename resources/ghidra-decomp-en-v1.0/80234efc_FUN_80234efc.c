// Function: FUN_80234efc
// Entry: 80234efc
// Size: 292 bytes

void FUN_80234efc(short *param_1,int param_2)

{
  param_1[2] = (ushort)*(byte *)(param_2 + 0x18) << 8;
  param_1[1] = (ushort)*(byte *)(param_2 + 0x19) << 8;
  *param_1 = (ushort)*(byte *)(param_2 + 0x1a) << 8;
  if (*(byte *)(param_2 + 0x1b) != 0) {
    *(float *)(param_1 + 4) =
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x1b)) - DOUBLE_803e72a0) /
         FLOAT_803e7294;
    if (*(float *)(param_1 + 4) == FLOAT_803e7298) {
      *(float *)(param_1 + 4) = FLOAT_803e7288;
    }
    *(float *)(param_1 + 4) = *(float *)(param_1 + 4) * *(float *)(*(int *)(param_1 + 0x28) + 4);
  }
  param_1[0x58] = param_1[0x58] | 0x2000;
  FUN_80030334((double)FLOAT_803e7298,param_1,0,0);
  if (*(int *)(param_1 + 0x2a) != 0) {
    FUN_80035974(param_1,(int)(short)(int)((float)((double)CONCAT44(0x43300000,
                                                                    (int)*(short *)(*(int *)(param_1
                                                                                            + 0x2a)
                                                                                   + 0x5a) ^
                                                                    0x80000000) - DOUBLE_803e72a8) *
                                          *(float *)(param_1 + 4)));
  }
  return;
}

