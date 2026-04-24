// Function: FUN_801884d8
// Entry: 801884d8
// Size: 508 bytes

void FUN_801884d8(uint param_1)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  
  iVar3 = *(int *)(param_1 + 0x4c);
  iVar4 = *(int *)(param_1 + 0xb8);
  if (*(short *)(param_1 + 0x46) == 0x548) {
    uVar2 = FUN_80020078((int)*(short *)(iVar4 + 6));
    if ((uVar2 != 0) && (uVar2 = FUN_80020078((int)*(short *)(iVar4 + 4)), uVar2 == 0)) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
    }
    uVar2 = FUN_80020078((int)*(short *)(iVar4 + 6));
    if ((uVar2 == 0) && (uVar2 = FUN_80020078((int)*(short *)(iVar4 + 4)), uVar2 != 0)) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_1,0xffffffff);
    }
  }
  else if (*(short *)(iVar4 + 10) == 0) {
    if ((*(char *)(iVar4 + 8) == '\0') &&
       (uVar2 = FUN_80020078((int)*(short *)(iVar4 + 6)), uVar2 != 0)) {
      *(undefined2 *)(iVar4 + 10) = 10;
    }
    if ((*(char *)(iVar4 + 8) == '\x01') && (*(float *)(iVar3 + 0xc) <= *(float *)(param_1 + 0x10)))
    {
      *(float *)(param_1 + 0x28) = *(float *)(param_1 + 0x28) - FLOAT_803e47e8;
      *(float *)(param_1 + 0x10) =
           *(float *)(param_1 + 0x28) * FLOAT_803dc074 + *(float *)(param_1 + 0x10);
      fVar1 = *(float *)(iVar3 + 0xc);
      if (*(float *)(param_1 + 0x10) <= fVar1) {
        *(float *)(param_1 + 0x10) = fVar1;
        *(float *)(param_1 + 0x28) = FLOAT_803e47ec * -*(float *)(param_1 + 0x28);
        fVar1 = *(float *)(param_1 + 0x28);
        if (fVar1 < FLOAT_803e47f0) {
          fVar1 = -fVar1;
        }
        if (fVar1 < FLOAT_803e47f4) {
          *(undefined *)(iVar4 + 8) = 2;
        }
      }
    }
  }
  else {
    *(short *)(iVar4 + 10) = *(short *)(iVar4 + 10) - (short)(int)FLOAT_803dc074;
    if (*(short *)(iVar4 + 10) < 1) {
      *(undefined *)(iVar4 + 8) = 1;
      if (*(char *)(iVar4 + 9) != '\0') {
        FUN_8000bb38(param_1,0x4bc);
        *(undefined *)(iVar4 + 9) = 0;
      }
      *(undefined2 *)(iVar4 + 10) = 0;
    }
  }
  return;
}

