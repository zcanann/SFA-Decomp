// Function: FUN_8010525c
// Entry: 8010525c
// Size: 220 bytes

void FUN_8010525c(int param_1)

{
  uint uVar1;
  double dVar2;
  
  uVar1 = FUN_80021884();
  uVar1 = (uVar1 & 0xffff) - (uint)*(ushort *)(param_1 + 2);
  if (0x8000 < (int)uVar1) {
    uVar1 = uVar1 - 0xffff;
  }
  if ((int)uVar1 < -0x8000) {
    uVar1 = uVar1 + 0xffff;
  }
  dVar2 = FUN_80021434((double)(float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) -
                                      DOUBLE_803e2318),
                       (double)(FLOAT_803e2324 /
                               (float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)(DAT_803de1a8 + 0xc2)) -
                                      DOUBLE_803e2378)),(double)FLOAT_803dc074);
  *(short *)(param_1 + 2) = *(short *)(param_1 + 2) + (short)(int)dVar2;
  return;
}

