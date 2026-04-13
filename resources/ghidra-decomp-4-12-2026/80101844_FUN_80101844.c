// Function: FUN_80101844
// Entry: 80101844
// Size: 232 bytes

void FUN_80101844(int param_1,int param_2)

{
  float fVar1;
  double dVar2;
  
  *(undefined4 *)(param_1 + 200) = *(undefined4 *)(param_1 + 0xcc);
  *(undefined4 *)(param_1 + 0xcc) = *(undefined4 *)(param_1 + 0xd0);
  *(undefined4 *)(param_1 + 0xd0) = *(undefined4 *)(param_1 + 0xd4);
  *(undefined4 *)(param_1 + 0xd4) = *(undefined4 *)(param_1 + 0xd8);
  dVar2 = FUN_80247f54((float *)(param_2 + 0x24));
  if ((double)FLOAT_803e22b0 < dVar2) {
    dVar2 = FUN_80293900(dVar2);
  }
  *(float *)(param_1 + 0xd8) = (float)dVar2;
  fVar1 = FLOAT_803e22b0;
  *(float *)(param_1 + 0xc4) = FLOAT_803e22b0;
  *(float *)(param_1 + 0xc4) = *(float *)(param_1 + 0xc4) + *(float *)(param_1 + 200);
  *(float *)(param_1 + 0xc4) = *(float *)(param_1 + 0xc4) + *(float *)(param_1 + 0xcc);
  *(float *)(param_1 + 0xc4) = *(float *)(param_1 + 0xc4) + *(float *)(param_1 + 0xd0);
  *(float *)(param_1 + 0xc4) = *(float *)(param_1 + 0xc4) + *(float *)(param_1 + 0xd4);
  *(float *)(param_1 + 0xc4) = *(float *)(param_1 + 0xc4) + *(float *)(param_1 + 0xd8);
  *(float *)(param_1 + 0xc4) = *(float *)(param_1 + 0xc4) * FLOAT_803e22d8;
  if (*(float *)(param_1 + 0xc4) < fVar1) {
    *(float *)(param_1 + 0xc4) = -*(float *)(param_1 + 0xc4);
  }
  return;
}

