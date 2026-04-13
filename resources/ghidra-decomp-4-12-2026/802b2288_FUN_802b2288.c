// Function: FUN_802b2288
// Entry: 802b2288
// Size: 208 bytes

void FUN_802b2288(double param_1,int param_2)

{
  float fVar1;
  float fVar2;
  double dVar3;
  
  fVar1 = *(float *)(param_2 + 0x24);
  fVar2 = FLOAT_803e8cb4;
  if ((FLOAT_803e8cb4 <= fVar1) && (fVar2 = fVar1, FLOAT_803e8ba8 < fVar1)) {
    fVar2 = FLOAT_803e8ba8;
  }
  *(float *)(param_2 + 0x24) = fVar2;
  fVar1 = *(float *)(param_2 + 0x28);
  fVar2 = FLOAT_803e8db4;
  if ((FLOAT_803e8db4 <= fVar1) && (fVar2 = fVar1, FLOAT_803e8d7c < fVar1)) {
    fVar2 = FLOAT_803e8d7c;
  }
  *(float *)(param_2 + 0x28) = fVar2;
  fVar1 = *(float *)(param_2 + 0x2c);
  fVar2 = FLOAT_803e8cb4;
  if ((FLOAT_803e8cb4 <= fVar1) && (fVar2 = fVar1, FLOAT_803e8ba8 < fVar1)) {
    fVar2 = FLOAT_803e8ba8;
  }
  *(float *)(param_2 + 0x2c) = fVar2;
  dVar3 = (double)(float)((double)*(float *)(param_2 + 0x28) * param_1);
  if ((double)FLOAT_803e8b70 < dVar3) {
    dVar3 = (double)FLOAT_803e8b70;
  }
  FUN_8002ba34((double)(float)((double)*(float *)(param_2 + 0x24) * param_1),dVar3,
               (double)(float)((double)*(float *)(param_2 + 0x2c) * param_1),param_2);
  return;
}

