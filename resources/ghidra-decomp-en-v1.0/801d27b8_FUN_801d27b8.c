// Function: FUN_801d27b8
// Entry: 801d27b8
// Size: 172 bytes

void FUN_801d27b8(int param_1,int param_2,int param_3)

{
  float fVar1;
  int iVar2;
  float *pfVar3;
  
  fVar1 = FLOAT_803e52fc;
  pfVar3 = *(float **)(param_1 + 0xb8);
  *pfVar3 = FLOAT_803e52fc;
  pfVar3[0xb] = fVar1;
  pfVar3[3] = *(float *)(param_1 + 8);
  *(undefined2 *)(pfVar3 + 0xd) = *(undefined2 *)(param_2 + 0x1a);
  if (*(short *)(pfVar3 + 0xd) < 0x708) {
    *(undefined2 *)(pfVar3 + 0xd) = 0x708;
  }
  *(float *)(param_1 + 0x10) = *(float *)(param_2 + 0xc) - FLOAT_803e5350;
  iVar2 = *(int *)(param_1 + 100);
  if (iVar2 != 0) {
    *(uint *)(iVar2 + 0x30) = *(uint *)(iVar2 + 0x30) | 0x810;
  }
  if (param_3 == 0) {
    FUN_801d1bfc(param_1,pfVar3,0);
  }
  FUN_80037200(param_1,3);
  return;
}

