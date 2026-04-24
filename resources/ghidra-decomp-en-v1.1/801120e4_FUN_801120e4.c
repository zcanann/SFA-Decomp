// Function: FUN_801120e4
// Entry: 801120e4
// Size: 108 bytes

double FUN_801120e4(int param_1)

{
  float fVar1;
  uint uVar2;
  uint uVar3;
  
  uVar3 = (uint)*(byte *)(*(int *)(param_1 + 0x4c) + 0x32);
  fVar1 = FLOAT_803e28ac;
  if ((uVar3 != 0) && (uVar2 = (uint)*(char *)(*(int *)(param_1 + 0xb8) + 0x354), uVar2 != 0)) {
    fVar1 = (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e28b0) /
            (float)((double)CONCAT44(0x43300000,uVar3) - DOUBLE_803e28b8);
  }
  return (double)fVar1;
}

