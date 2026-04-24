// Function: FUN_801dafdc
// Entry: 801dafdc
// Size: 188 bytes

void FUN_801dafdc(short *param_1,int param_2)

{
  float fVar1;
  
  param_1[2] = (*(byte *)(param_2 + 0x18) - 0x7f) * 0x80;
  param_1[1] = (*(byte *)(param_2 + 0x19) - 0x7f) * 0x80;
  *param_1 = (ushort)*(byte *)(param_2 + 0x1a) << 8;
  *(undefined4 *)(param_1 + 4) = *(undefined4 *)(param_2 + 0x1c);
  fVar1 = *(float *)(param_1 + 4);
  FUN_80035b50(param_1,(int)(FLOAT_803e5540 * fVar1),(int)(FLOAT_803e5544 * fVar1),
               (int)(FLOAT_803e5548 * fVar1));
  param_1[0x58] = param_1[0x58] | 0x4000;
  return;
}

