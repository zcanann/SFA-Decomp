// Function: FUN_8021e414
// Entry: 8021e414
// Size: 220 bytes

undefined4 FUN_8021e414(int param_1,uint *param_2)

{
  float fVar1;
  undefined4 uVar2;
  
  fVar1 = FLOAT_803e6aa8;
  param_2[0xa5] = (uint)FLOAT_803e6aa8;
  param_2[0xa1] = (uint)fVar1;
  param_2[0xa0] = (uint)fVar1;
  *(float *)(param_1 + 0x24) = fVar1;
  *(float *)(param_1 + 0x28) = fVar1;
  *(float *)(param_1 + 0x2c) = fVar1;
  *param_2 = *param_2 | 0x200000;
  if (*(char *)((int)param_2 + 0x27a) != '\0') {
    *(undefined2 *)(param_2 + 0xce) = 0;
    param_2[0xa8] = (uint)FLOAT_803e6b24;
    param_2[0xae] = (uint)FLOAT_803e6b28;
    if ((int)*(short *)(param_1 + 0xa0) != (int)DAT_803dc32c) {
      FUN_80030334(param_1,(int)DAT_803dc32c,0);
    }
  }
  if ((float)param_2[0xa6] < FLOAT_803e6b2c) {
    *(undefined2 *)(param_2 + 0xcd) = 0;
    *(undefined2 *)((int)param_2 + 0x336) = 0;
    param_2[0xa6] = (uint)FLOAT_803e6aa8;
  }
  if (((float)param_2[0xa7] <= FLOAT_803e6aa8) || ((float)param_2[0xa6] <= FLOAT_803e6aa8)) {
    uVar2 = 0;
  }
  else {
    uVar2 = 3;
  }
  return uVar2;
}

