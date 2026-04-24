// Function: FUN_80191c50
// Entry: 80191c50
// Size: 168 bytes

void FUN_80191c50(short *param_1,int param_2)

{
  param_1[2] = (ushort)*(byte *)(param_2 + 0x18) << 8;
  param_1[1] = (ushort)*(byte *)(param_2 + 0x19) << 8;
  *param_1 = (ushort)*(byte *)(param_2 + 0x1a) << 8;
  if (*(byte *)(param_2 + 0x1b) != 0) {
    *(float *)(param_1 + 4) =
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x1b)) - DOUBLE_803e3f28) /
         FLOAT_803e3f24;
    if (*(float *)(param_1 + 4) == FLOAT_803e3f04) {
      *(float *)(param_1 + 4) = FLOAT_803e3f00;
    }
    *(float *)(param_1 + 4) = *(float *)(param_1 + 4) * *(float *)(*(int *)(param_1 + 0x28) + 4);
  }
  param_1[0x58] = param_1[0x58] | 0x2000;
  return;
}

