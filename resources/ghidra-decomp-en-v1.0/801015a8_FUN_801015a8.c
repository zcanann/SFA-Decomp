// Function: FUN_801015a8
// Entry: 801015a8
// Size: 232 bytes

void FUN_801015a8(int param_1,int param_2)

{
  float fVar1;
  double dVar2;
  
  *(undefined4 *)(param_1 + 200) = *(undefined4 *)(param_1 + 0xcc);
  *(undefined4 *)(param_1 + 0xcc) = *(undefined4 *)(param_1 + 0xd0);
  *(undefined4 *)(param_1 + 0xd0) = *(undefined4 *)(param_1 + 0xd4);
  *(undefined4 *)(param_1 + 0xd4) = *(undefined4 *)(param_1 + 0xd8);
  dVar2 = (double)FUN_802477f0(param_2 + 0x24);
  if ((double)FLOAT_803e1630 < dVar2) {
    dVar2 = (double)FUN_802931a0();
  }
  *(float *)(param_1 + 0xd8) = (float)dVar2;
  fVar1 = FLOAT_803e1630;
  *(float *)(param_1 + 0xc4) = FLOAT_803e1630;
  *(float *)(param_1 + 0xc4) = *(float *)(param_1 + 0xc4) + *(float *)(param_1 + 200);
  *(float *)(param_1 + 0xc4) = *(float *)(param_1 + 0xc4) + *(float *)(param_1 + 0xcc);
  *(float *)(param_1 + 0xc4) = *(float *)(param_1 + 0xc4) + *(float *)(param_1 + 0xd0);
  *(float *)(param_1 + 0xc4) = *(float *)(param_1 + 0xc4) + *(float *)(param_1 + 0xd4);
  *(float *)(param_1 + 0xc4) = *(float *)(param_1 + 0xc4) + *(float *)(param_1 + 0xd8);
  *(float *)(param_1 + 0xc4) = *(float *)(param_1 + 0xc4) * FLOAT_803e1658;
  if (*(float *)(param_1 + 0xc4) < fVar1) {
    *(float *)(param_1 + 0xc4) = -*(float *)(param_1 + 0xc4);
  }
  return;
}

