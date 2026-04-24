// Function: FUN_802355e8
// Entry: 802355e8
// Size: 200 bytes

void FUN_802355e8(short *param_1,int param_2)

{
  param_1[2] = (ushort)*(byte *)(param_2 + 0x18) << 8;
  param_1[1] = (ushort)*(byte *)(param_2 + 0x19) << 8;
  *param_1 = (ushort)*(byte *)(param_2 + 0x1a) << 8;
  if (*(byte *)(param_2 + 0x1b) != 0) {
    *(float *)(param_1 + 4) =
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x1b)) - DOUBLE_803e72d8) /
         FLOAT_803e72f4;
    if (*(float *)(param_1 + 4) == FLOAT_803e72b0) {
      *(float *)(param_1 + 4) = FLOAT_803e72e8;
    }
    *(float *)(param_1 + 4) = *(float *)(param_1 + 4) * *(float *)(*(int *)(param_1 + 0x28) + 4);
  }
  param_1[0x58] = param_1[0x58] | 0x2000;
  FUN_80030334((double)FLOAT_803e72b0,param_1,0,0);
  return;
}

