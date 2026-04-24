// Function: FUN_8013a3f0
// Entry: 8013a3f0
// Size: 252 bytes

undefined4 FUN_8013a3f0(double param_1,int param_2,int param_3,uint param_4)

{
  float fVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_2 + 0xb8);
  if (*(int *)(iVar2 + 0x20) == param_3) {
    if (*(short *)(param_2 + 0xa0) == param_3) {
      *(float *)(iVar2 + 0x34) = (float)param_1;
      *(uint *)(iVar2 + 0x54) = *(uint *)(iVar2 + 0x54) | param_4;
    }
    return 1;
  }
  if ((param_4 & 0x4000000) != 0) {
    *(float *)(iVar2 + 0x18) = FLOAT_803e247c;
  }
  *(int *)(iVar2 + 0x20) = param_3;
  *(float *)(iVar2 + 0x38) = (float)param_1;
  *(uint *)(iVar2 + 0x50) = param_4;
  if ((param_4 & 0x20) == 0) {
    *(uint *)(iVar2 + 0x54) = *(uint *)(iVar2 + 0x54) & 0xffffffdf;
  }
  if ((param_4 & 0x40) == 0) {
    *(uint *)(iVar2 + 0x54) = *(uint *)(iVar2 + 0x54) & 0xffffffbf;
  }
  if ((param_4 & 0x80) == 0) {
    *(uint *)(iVar2 + 0x54) = *(uint *)(iVar2 + 0x54) & 0xffffff7f;
  }
  if ((param_4 & 0x100) == 0) {
    *(uint *)(iVar2 + 0x54) = *(uint *)(iVar2 + 0x54) & 0xfffffeff;
  }
  fVar1 = FLOAT_803e23e8;
  *(float *)(iVar2 + 0x40) = FLOAT_803e23e8;
  *(float *)(iVar2 + 0x44) = fVar1;
  *(float *)(iVar2 + 0x48) = fVar1;
  *(float *)(iVar2 + 0x4c) = fVar1;
  if (FLOAT_803e247c <= *(float *)(iVar2 + 0x18)) {
    return 1;
  }
  return 0;
}

