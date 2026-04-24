// Function: FUN_801db5cc
// Entry: 801db5cc
// Size: 188 bytes

void FUN_801db5cc(short *param_1,int param_2)

{
  float fVar1;
  
  param_1[2] = (*(byte *)(param_2 + 0x18) - 0x7f) * 0x80;
  param_1[1] = (*(byte *)(param_2 + 0x19) - 0x7f) * 0x80;
  *param_1 = (ushort)*(byte *)(param_2 + 0x1a) << 8;
  *(undefined4 *)(param_1 + 4) = *(undefined4 *)(param_2 + 0x1c);
  fVar1 = *(float *)(param_1 + 4);
  FUN_80035c48((int)param_1,(short)(int)(FLOAT_803e61d8 * fVar1),
               (short)(int)(FLOAT_803e61dc * fVar1),(short)(int)(FLOAT_803e61e0 * fVar1));
  param_1[0x58] = param_1[0x58] | 0x4000;
  return;
}

