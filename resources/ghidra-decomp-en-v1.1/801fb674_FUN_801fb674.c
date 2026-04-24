// Function: FUN_801fb674
// Entry: 801fb674
// Size: 404 bytes

void FUN_801fb674(uint param_1)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  short *psVar4;
  
  iVar3 = *(int *)(param_1 + 0x4c);
  psVar4 = *(short **)(param_1 + 0xb8);
  if (*(short *)(param_1 + 0x46) == 0x548) {
    uVar2 = FUN_80020078((int)psVar4[1]);
    if ((uVar2 != 0) && (uVar2 = FUN_80020078((int)*psVar4), uVar2 == 0)) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
    }
    uVar2 = FUN_80020078((int)psVar4[1]);
    if ((uVar2 == 0) && (uVar2 = FUN_80020078((int)*psVar4), uVar2 != 0)) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_1,0xffffffff);
    }
  }
  else if (psVar4[3] == 0) {
    if ((psVar4[2] == 0) && (uVar2 = FUN_80020078((int)psVar4[1]), uVar2 != 0)) {
      psVar4[3] = 0x5a;
    }
    fVar1 = FLOAT_803e6d70;
    if (psVar4[2] == 1) {
      if (*(float *)(iVar3 + 0xc) - FLOAT_803e6d70 < *(float *)(param_1 + 0x10)) {
        *(float *)(param_1 + 0x10) = -(FLOAT_803e6d74 * FLOAT_803dc074 - *(float *)(param_1 + 0x10))
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
    psVar4[3] = psVar4[3] - (short)(int)FLOAT_803dc074;
    if (psVar4[3] < 1) {
      psVar4[2] = 1;
      FUN_8000bb38(param_1,0x54);
      psVar4[3] = 0;
    }
  }
  return;
}

