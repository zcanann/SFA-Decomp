// Function: FUN_801781f4
// Entry: 801781f4
// Size: 212 bytes

void FUN_801781f4(int param_1)

{
  float fVar1;
  int iVar2;
  float *pfVar3;
  
  pfVar3 = *(float **)(param_1 + 0xb8);
  *pfVar3 = *pfVar3 + FLOAT_803db414;
  fVar1 = *pfVar3;
  if (fVar1 <= FLOAT_803e3630) {
    if ((FLOAT_803e3634 < fVar1) && (*(char *)((int)pfVar3 + 0x11) == '\0')) {
      FUN_80035df4(param_1,0x1a,1,0);
    }
  }
  else {
    *pfVar3 = fVar1 - FLOAT_803e3630;
    iVar2 = FUN_8017805c(param_1,pfVar3);
    if (iVar2 == 0) {
      return;
    }
  }
  *(float *)(param_1 + 0xc) = *(float *)(param_1 + 0x24) * *pfVar3 + pfVar3[1];
  *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x28) * *pfVar3 + pfVar3[2];
  *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x2c) * *pfVar3 + pfVar3[3];
  return;
}

