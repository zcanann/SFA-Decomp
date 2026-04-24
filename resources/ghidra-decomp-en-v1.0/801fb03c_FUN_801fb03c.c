// Function: FUN_801fb03c
// Entry: 801fb03c
// Size: 404 bytes

void FUN_801fb03c(int param_1)

{
  float fVar1;
  int iVar2;
  int iVar3;
  short *psVar4;
  
  iVar3 = *(int *)(param_1 + 0x4c);
  psVar4 = *(short **)(param_1 + 0xb8);
  if (*(short *)(param_1 + 0x46) == 0x548) {
    iVar3 = FUN_8001ffb4((int)psVar4[1]);
    if ((iVar3 != 0) && (iVar3 = FUN_8001ffb4((int)*psVar4), iVar3 == 0)) {
      (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
    }
    iVar3 = FUN_8001ffb4((int)psVar4[1]);
    if ((iVar3 == 0) && (iVar3 = FUN_8001ffb4((int)*psVar4), iVar3 != 0)) {
      (**(code **)(*DAT_803dca54 + 0x48))(1,param_1,0xffffffff);
    }
  }
  else if (psVar4[3] == 0) {
    if ((psVar4[2] == 0) && (iVar2 = FUN_8001ffb4((int)psVar4[1]), iVar2 != 0)) {
      psVar4[3] = 0x5a;
    }
    fVar1 = FLOAT_803e60d8;
    if (psVar4[2] == 1) {
      if (*(float *)(iVar3 + 0xc) - FLOAT_803e60d8 < *(float *)(param_1 + 0x10)) {
        *(float *)(param_1 + 0x10) = -(FLOAT_803e60dc * FLOAT_803db414 - *(float *)(param_1 + 0x10))
        ;
        fVar1 = *(float *)(iVar3 + 0xc) - fVar1;
        if (*(float *)(param_1 + 0x10) < fVar1) {
          *(float *)(param_1 + 0x10) = fVar1;
          psVar4[2] = 2;
        }
      }
    }
  }
  else {
    psVar4[3] = psVar4[3] - (short)(int)FLOAT_803db414;
    if (psVar4[3] < 1) {
      psVar4[2] = 1;
      FUN_8000bb18(param_1,0x54);
      psVar4[3] = 0;
    }
  }
  return;
}

