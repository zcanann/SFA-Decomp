// Function: FUN_80070234
// Entry: 80070234
// Size: 132 bytes

void FUN_80070234(float *param_1)

{
  float fVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  
  fVar2 = FLOAT_803dee9c;
  fVar1 = FLOAT_803dee98;
  iVar3 = 0;
  iVar4 = 4;
  do {
    if (iVar3 == 0) {
      *param_1 = fVar1;
    }
    else {
      *param_1 = fVar2;
    }
    if (iVar3 == 1) {
      param_1[1] = fVar1;
    }
    else {
      param_1[1] = fVar2;
    }
    if (iVar3 == 2) {
      param_1[2] = fVar1;
    }
    else {
      param_1[2] = fVar2;
    }
    if (iVar3 == 3) {
      param_1[3] = fVar1;
    }
    else {
      param_1[3] = fVar2;
    }
    param_1 = param_1 + 4;
    iVar3 = iVar3 + 1;
    iVar4 = iVar4 + -1;
  } while (iVar4 != 0);
  return;
}

