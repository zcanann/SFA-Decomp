// Function: FUN_801facb4
// Entry: 801facb4
// Size: 764 bytes

void FUN_801facb4(int param_1)

{
  float fVar1;
  int iVar2;
  short *psVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  psVar3 = *(short **)(param_1 + 0xb8);
  if (*(char *)(iVar4 + 0x19) == '\x01') {
    iVar2 = FUN_8001ffb4((int)*psVar3);
    if ((iVar2 != 0) && (*(float *)(iVar4 + 0x10) - FLOAT_803e60d0 < *(float *)(param_1 + 0x14))) {
      *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) - FLOAT_803e60d4;
      iVar2 = FUN_8001ffb4(0x503);
      if ((iVar2 != 0) && (iVar2 = FUN_8001ffb4(0x504), iVar2 != 0)) {
        FUN_800200e8(0x4ed,1);
      }
      fVar1 = *(float *)(iVar4 + 0x10) - FLOAT_803e60d0;
      if (fVar1 < *(float *)(param_1 + 0x14)) {
        return;
      }
      *(float *)(param_1 + 0x14) = fVar1;
      iVar4 = FUN_8001ffb4(0x503);
      if (iVar4 == 0) {
        return;
      }
      iVar4 = FUN_8001ffb4(0x504);
      if (iVar4 == 0) {
        return;
      }
      FUN_800200e8(0x4ec,1);
      return;
    }
    iVar2 = FUN_8001ffb4((int)*psVar3);
    if ((iVar2 == 0) && (*(float *)(param_1 + 0x14) < *(float *)(iVar4 + 0x10))) {
      *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) - FLOAT_803e60d4;
      iVar2 = FUN_8001ffb4(0x503);
      if ((iVar2 != 0) && (iVar2 = FUN_8001ffb4(0x504), iVar2 != 0)) {
        FUN_800200e8(0x4ed,1);
      }
      if (*(float *)(iVar4 + 0x10) < *(float *)(param_1 + 0x14)) {
        *(float *)(param_1 + 0x14) = *(float *)(iVar4 + 0x10);
        iVar4 = FUN_8001ffb4(0x503);
        if ((iVar4 == 0) && (iVar4 = FUN_8001ffb4(0x504), iVar4 == 0)) {
          FUN_800200e8(0x4ea,0);
          FUN_800200e8(0x4ec,0);
        }
      }
    }
  }
  else {
    iVar2 = FUN_8001ffb4((int)*psVar3);
    if ((iVar2 != 0) && (*(float *)(param_1 + 0x14) < FLOAT_803e60d0 + *(float *)(iVar4 + 0x10))) {
      *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) + FLOAT_803e60d4;
      iVar2 = FUN_8001ffb4(0x503);
      if ((iVar2 != 0) && (iVar2 = FUN_8001ffb4(0x504), iVar2 != 0)) {
        FUN_800200e8(0x4ed,1);
      }
      fVar1 = FLOAT_803e60d0 + *(float *)(iVar4 + 0x10);
      if (*(float *)(param_1 + 0x14) < fVar1) {
        return;
      }
      *(float *)(param_1 + 0x14) = fVar1;
      iVar4 = FUN_8001ffb4(0x503);
      if (iVar4 == 0) {
        return;
      }
      iVar4 = FUN_8001ffb4(0x504);
      if (iVar4 == 0) {
        return;
      }
      FUN_800200e8(0x4ec,1);
      return;
    }
    iVar2 = FUN_8001ffb4((int)*psVar3);
    if ((iVar2 == 0) && (*(float *)(iVar4 + 0x10) < *(float *)(param_1 + 0x14))) {
      *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) - FLOAT_803e60d4;
      iVar2 = FUN_8001ffb4(0x503);
      if ((iVar2 != 0) && (iVar2 = FUN_8001ffb4(0x504), iVar2 != 0)) {
        FUN_800200e8(0x4ed,1);
      }
      if (*(float *)(param_1 + 0x14) < *(float *)(iVar4 + 0x10)) {
        *(float *)(param_1 + 0x14) = *(float *)(iVar4 + 0x10);
        iVar4 = FUN_8001ffb4(0x503);
        if ((iVar4 == 0) && (iVar4 = FUN_8001ffb4(0x504), iVar4 == 0)) {
          FUN_800200e8(0x4ea,0);
          FUN_800200e8(0x4ec,0);
        }
      }
    }
  }
  return;
}

