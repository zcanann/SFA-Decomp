// Function: FUN_80104fc0
// Entry: 80104fc0
// Size: 220 bytes

void FUN_80104fc0(double param_1,int param_2)

{
  uint uVar1;
  double dVar2;
  
  uVar1 = FUN_800217c0((double)(*(float *)(param_2 + 0x1c) -
                               (float)(param_1 + (double)*(float *)(DAT_803dd530 + 0x8c))));
  uVar1 = (uVar1 & 0xffff) - ((int)*(short *)(param_2 + 2) & 0xffffU);
  if (0x8000 < (int)uVar1) {
    uVar1 = uVar1 - 0xffff;
  }
  if ((int)uVar1 < -0x8000) {
    uVar1 = uVar1 + 0xffff;
  }
  dVar2 = (double)FUN_80021370((double)(float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) -
                                              DOUBLE_803e1698),
                               (double)(FLOAT_803e16a4 /
                                       (float)((double)CONCAT44(0x43300000,
                                                                (uint)*(byte *)(DAT_803dd530 + 0xc2)
                                                               ) - DOUBLE_803e16f8)),
                               (double)FLOAT_803db414);
  *(short *)(param_2 + 2) = *(short *)(param_2 + 2) + (short)(int)dVar2;
  return;
}

