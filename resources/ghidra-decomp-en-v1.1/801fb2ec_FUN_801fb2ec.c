// Function: FUN_801fb2ec
// Entry: 801fb2ec
// Size: 764 bytes

void FUN_801fb2ec(int param_1)

{
  float fVar1;
  uint uVar2;
  short *psVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  psVar3 = *(short **)(param_1 + 0xb8);
  if (*(char *)(iVar4 + 0x19) == '\x01') {
    uVar2 = FUN_80020078((int)*psVar3);
    if ((uVar2 == 0) || (*(float *)(param_1 + 0x14) <= *(float *)(iVar4 + 0x10) - FLOAT_803e6d68)) {
      uVar2 = FUN_80020078((int)*psVar3);
      if ((uVar2 == 0) && (*(float *)(param_1 + 0x14) < *(float *)(iVar4 + 0x10))) {
        *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) - FLOAT_803e6d6c;
        uVar2 = FUN_80020078(0x503);
        if ((uVar2 != 0) && (uVar2 = FUN_80020078(0x504), uVar2 != 0)) {
          FUN_800201ac(0x4ed,1);
        }
        if (*(float *)(iVar4 + 0x10) < *(float *)(param_1 + 0x14)) {
          *(float *)(param_1 + 0x14) = *(float *)(iVar4 + 0x10);
          uVar2 = FUN_80020078(0x503);
          if ((uVar2 == 0) && (uVar2 = FUN_80020078(0x504), uVar2 == 0)) {
            FUN_800201ac(0x4ea,0);
            FUN_800201ac(0x4ec,0);
          }
        }
      }
    }
    else {
      *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) - FLOAT_803e6d6c;
      uVar2 = FUN_80020078(0x503);
      if ((uVar2 != 0) && (uVar2 = FUN_80020078(0x504), uVar2 != 0)) {
        FUN_800201ac(0x4ed,1);
      }
      fVar1 = *(float *)(iVar4 + 0x10) - FLOAT_803e6d68;
      if (*(float *)(param_1 + 0x14) <= fVar1) {
        *(float *)(param_1 + 0x14) = fVar1;
        uVar2 = FUN_80020078(0x503);
        if ((uVar2 != 0) && (uVar2 = FUN_80020078(0x504), uVar2 != 0)) {
          FUN_800201ac(0x4ec,1);
        }
      }
    }
  }
  else {
    uVar2 = FUN_80020078((int)*psVar3);
    if ((uVar2 == 0) || (FLOAT_803e6d68 + *(float *)(iVar4 + 0x10) <= *(float *)(param_1 + 0x14))) {
      uVar2 = FUN_80020078((int)*psVar3);
      if ((uVar2 == 0) && (*(float *)(iVar4 + 0x10) < *(float *)(param_1 + 0x14))) {
        *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) - FLOAT_803e6d6c;
        uVar2 = FUN_80020078(0x503);
        if ((uVar2 != 0) && (uVar2 = FUN_80020078(0x504), uVar2 != 0)) {
          FUN_800201ac(0x4ed,1);
        }
        if (*(float *)(param_1 + 0x14) < *(float *)(iVar4 + 0x10)) {
          *(float *)(param_1 + 0x14) = *(float *)(iVar4 + 0x10);
          uVar2 = FUN_80020078(0x503);
          if ((uVar2 == 0) && (uVar2 = FUN_80020078(0x504), uVar2 == 0)) {
            FUN_800201ac(0x4ea,0);
            FUN_800201ac(0x4ec,0);
          }
        }
      }
    }
    else {
      *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) + FLOAT_803e6d6c;
      uVar2 = FUN_80020078(0x503);
      if ((uVar2 != 0) && (uVar2 = FUN_80020078(0x504), uVar2 != 0)) {
        FUN_800201ac(0x4ed,1);
      }
      fVar1 = FLOAT_803e6d68 + *(float *)(iVar4 + 0x10);
      if (fVar1 <= *(float *)(param_1 + 0x14)) {
        *(float *)(param_1 + 0x14) = fVar1;
        uVar2 = FUN_80020078(0x503);
        if ((uVar2 != 0) && (uVar2 = FUN_80020078(0x504), uVar2 != 0)) {
          FUN_800201ac(0x4ec,1);
        }
      }
    }
  }
  return;
}

