// Function: FUN_801a7424
// Entry: 801a7424
// Size: 212 bytes

void FUN_801a7424(short *param_1,int param_2)

{
  uint uVar1;
  undefined *puVar2;
  
  puVar2 = *(undefined **)(param_1 + 0x5c);
  puVar2[1] = 1;
  *param_1 = (ushort)*(byte *)(param_2 + 0x1f) << 8;
  *(code **)(param_1 + 0x5e) = FUN_801a71dc;
  param_1[0x58] = param_1[0x58] | 0x2000;
  *(float *)(param_1 + 4) =
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x21)) - DOUBLE_803e5178) *
       FLOAT_803e516c;
  if (*(float *)(param_1 + 4) == FLOAT_803e5170) {
    *(float *)(param_1 + 4) = FLOAT_803e5168;
  }
  *(float *)(param_1 + 4) = *(float *)(param_1 + 4) * *(float *)(*(int *)(param_1 + 0x28) + 4);
  if ((int)*(short *)(param_2 + 0x1a) == 0xffffffff) {
    *puVar2 = 0;
  }
  else {
    uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x1a));
    *puVar2 = (char)uVar1;
  }
  return;
}

