// Function: FUN_80187f80
// Entry: 80187f80
// Size: 508 bytes

void FUN_80187f80(int param_1)

{
  float fVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  iVar3 = *(int *)(param_1 + 0x4c);
  iVar4 = *(int *)(param_1 + 0xb8);
  if (*(short *)(param_1 + 0x46) == 0x548) {
    iVar3 = FUN_8001ffb4((int)*(short *)(iVar4 + 6));
    if ((iVar3 != 0) && (iVar3 = FUN_8001ffb4((int)*(short *)(iVar4 + 4)), iVar3 == 0)) {
      (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
    }
    iVar3 = FUN_8001ffb4((int)*(short *)(iVar4 + 6));
    if ((iVar3 == 0) && (iVar3 = FUN_8001ffb4((int)*(short *)(iVar4 + 4)), iVar3 != 0)) {
      (**(code **)(*DAT_803dca54 + 0x48))(1,param_1,0xffffffff);
    }
  }
  else if (*(short *)(iVar4 + 10) == 0) {
    if ((*(char *)(iVar4 + 8) == '\0') &&
       (iVar2 = FUN_8001ffb4((int)*(short *)(iVar4 + 6)), iVar2 != 0)) {
      *(undefined2 *)(iVar4 + 10) = 10;
    }
    if ((*(char *)(iVar4 + 8) == '\x01') && (*(float *)(iVar3 + 0xc) <= *(float *)(param_1 + 0x10)))
    {
      *(float *)(param_1 + 0x28) = *(float *)(param_1 + 0x28) - FLOAT_803e3b50;
      *(float *)(param_1 + 0x10) =
           *(float *)(param_1 + 0x28) * FLOAT_803db414 + *(float *)(param_1 + 0x10);
      fVar1 = *(float *)(iVar3 + 0xc);
      if (*(float *)(param_1 + 0x10) <= fVar1) {
        *(float *)(param_1 + 0x10) = fVar1;
        *(float *)(param_1 + 0x28) = FLOAT_803e3b54 * -*(float *)(param_1 + 0x28);
        fVar1 = *(float *)(param_1 + 0x28);
        if (fVar1 < FLOAT_803e3b58) {
          fVar1 = -fVar1;
        }
        if (fVar1 < FLOAT_803e3b5c) {
          *(undefined *)(iVar4 + 8) = 2;
        }
      }
    }
  }
  else {
    *(short *)(iVar4 + 10) = *(short *)(iVar4 + 10) - (short)(int)FLOAT_803db414;
    if (*(short *)(iVar4 + 10) < 1) {
      *(undefined *)(iVar4 + 8) = 1;
      if (*(char *)(iVar4 + 9) != '\0') {
        FUN_8000bb18(param_1,0x4bc);
        *(undefined *)(iVar4 + 9) = 0;
      }
      *(undefined2 *)(iVar4 + 10) = 0;
    }
  }
  return;
}

