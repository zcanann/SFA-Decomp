// Function: FUN_802b1b28
// Entry: 802b1b28
// Size: 208 bytes

void FUN_802b1b28(double param_1,int param_2)

{
  float fVar1;
  float fVar2;
  double dVar3;
  
  fVar1 = *(float *)(param_2 + 0x24);
  fVar2 = FLOAT_803e801c;
  if ((FLOAT_803e801c <= fVar1) && (fVar2 = fVar1, FLOAT_803e7f10 < fVar1)) {
    fVar2 = FLOAT_803e7f10;
  }
  *(float *)(param_2 + 0x24) = fVar2;
  fVar1 = *(float *)(param_2 + 0x28);
  fVar2 = FLOAT_803e811c;
  if ((FLOAT_803e811c <= fVar1) && (fVar2 = fVar1, FLOAT_803e80e4 < fVar1)) {
    fVar2 = FLOAT_803e80e4;
  }
  *(float *)(param_2 + 0x28) = fVar2;
  fVar1 = *(float *)(param_2 + 0x2c);
  fVar2 = FLOAT_803e801c;
  if ((FLOAT_803e801c <= fVar1) && (fVar2 = fVar1, FLOAT_803e7f10 < fVar1)) {
    fVar2 = FLOAT_803e7f10;
  }
  *(float *)(param_2 + 0x2c) = fVar2;
  dVar3 = (double)(float)((double)*(float *)(param_2 + 0x28) * param_1);
  if ((double)FLOAT_803e7ed8 < dVar3) {
    dVar3 = (double)FLOAT_803e7ed8;
  }
  FUN_8002b95c((double)(float)((double)*(float *)(param_2 + 0x24) * param_1),dVar3,
               (double)(float)((double)*(float *)(param_2 + 0x2c) * param_1));
  return;
}

