// Function: FUN_8018b9f8
// Entry: 8018b9f8
// Size: 196 bytes

void FUN_8018b9f8(int param_1)

{
  int iVar1;
  char cVar2;
  float *pfVar3;
  
  pfVar3 = *(float **)(param_1 + 0xb8);
  iVar1 = FUN_80038024();
  if ((iVar1 != 0) && (cVar2 = FUN_801334e0(), cVar2 == '\0')) {
    *pfVar3 = FLOAT_803e3c80;
  }
  if (FLOAT_803e3c84 < *pfVar3) {
    if ((*(byte *)(param_1 + 0xaf) & 4) == 0) {
      *pfVar3 = FLOAT_803e3c84;
    }
    else {
      *pfVar3 = *pfVar3 - FLOAT_803db414;
      FUN_8012ef30((int)*(short *)(*(int *)(param_1 + 0x50) +
                                   (uint)*(byte *)(*(int *)(param_1 + 0x4c) + 0x19) * 2 + 0x7c));
    }
  }
  if ((*(uint *)(*(int *)(param_1 + 0x50) + 0x44) & 1) != 0) {
    FUN_80041018(param_1);
  }
  return;
}

