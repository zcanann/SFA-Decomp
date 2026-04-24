// Function: FUN_801695d4
// Entry: 801695d4
// Size: 140 bytes

void FUN_801695d4(int param_1)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float *pfVar4;
  
  pfVar4 = *(float **)(param_1 + 0xb8);
  fVar1 = *pfVar4;
  fVar2 = pfVar4[2];
  if (fVar1 != fVar2) {
    fVar3 = pfVar4[1];
    if (fVar3 <= FLOAT_803e30d4) {
      if (fVar1 <= fVar2) {
        *pfVar4 = fVar2;
      }
      else {
        *pfVar4 = fVar3 * FLOAT_803db414 + fVar1;
      }
    }
    else if (fVar2 <= fVar1) {
      *pfVar4 = fVar2;
    }
    else {
      *pfVar4 = fVar3 * FLOAT_803db414 + fVar1;
    }
  }
  FUN_80030334((double)*pfVar4,param_1,*(undefined *)(pfVar4 + 3),0);
  return;
}

