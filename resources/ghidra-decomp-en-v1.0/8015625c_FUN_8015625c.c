// Function: FUN_8015625c
// Entry: 8015625c
// Size: 720 bytes

void FUN_8015625c(int param_1,int param_2)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  double dVar4;
  
  if (FLOAT_803e2aa8 < *(float *)(param_2 + 0x328)) {
    *(float *)(param_2 + 0x328) = FLOAT_803e2aac;
  }
  *(undefined *)(*(int *)(param_1 + 0x54) + 0x70) = 0;
  FUN_80035df4(param_1,10,1,0);
  if ((*(uint *)(param_2 + 0x2dc) & 0x40000000) != 0) {
    FUN_8000bb18(param_1,0x261);
  }
  *(float *)(param_2 + 0x328) = *(float *)(param_2 + 0x328) - FLOAT_803db414;
  if (*(float *)(param_2 + 0x328) <= FLOAT_803e2a98) {
    if ((*(uint *)(param_2 + 0x2dc) & 0x600) == 0) {
      uVar2 = FUN_800221a0(600,0x352);
      *(float *)(param_2 + 0x328) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e2aa0);
    }
    else {
      uVar2 = FUN_800221a0(0x96,0xfa);
      *(float *)(param_2 + 0x328) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e2aa0);
    }
    FUN_8000bb18(param_1,0x262);
  }
  if ((*(uint *)(param_2 + 0x2dc) & 0x40000000) != 0) {
    FUN_80030334((double)FLOAT_803e2a98,param_1,3,*(undefined *)(param_2 + 0x323));
  }
  fVar1 = FLOAT_803e2a98;
  if (*(float *)(param_2 + 0x324) <= FLOAT_803e2a98) {
    if ((*(uint *)(param_2 + 0x2dc) & 0x400) != 0) {
      *(float *)(param_2 + 0x324) = FLOAT_803e2ab0;
    }
  }
  else {
    *(float *)(param_2 + 0x324) = *(float *)(param_2 + 0x324) - FLOAT_803db414;
    if (*(float *)(param_2 + 0x324) <= fVar1) {
      *(float *)(param_2 + 0x324) = FLOAT_803e2ab0;
      *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0x10000;
    }
  }
  if ((*(uint *)(param_2 + 0x2dc) & 0x8000000) == 0) {
    iVar3 = *(int *)(param_2 + 0x29c);
    dVar4 = (double)FUN_8014cb54((double)*(float *)(iVar3 + 0x18),
                                 (double)(FLOAT_803e2ab8 + *(float *)(iVar3 + 0x1c)),
                                 (double)*(float *)(iVar3 + 0x20),(double)FLOAT_803e2abc,
                                 (double)FLOAT_803e2ac0,(double)FLOAT_803e2ac4,
                                 (double)*(float *)(param_2 + 0x304),param_1);
  }
  else {
    dVar4 = (double)FLOAT_803e2ab4;
  }
  if ((((double)FLOAT_803e2a98 < dVar4) && (*(float *)(param_1 + 0x28) < FLOAT_803e2ac8)) ||
     ((*(uint *)(param_2 + 0x2dc) & 0x8000000) != 0)) {
    *(undefined *)(param_2 + 0x33a) = 1;
  }
  if ((*(char *)(param_2 + 0x33a) == '\0') || (dVar4 <= (double)FLOAT_803e2a98)) {
    *(undefined *)(param_2 + 0x33a) = 0;
    if (FLOAT_803e2adc < *(float *)(param_2 + 0x308)) {
      *(float *)(param_2 + 0x308) = -(FLOAT_803e2ae0 * FLOAT_803db414 - *(float *)(param_2 + 0x308))
      ;
    }
  }
  else {
    *(float *)(param_2 + 0x308) = FLOAT_803e2acc;
    if (*(short *)(param_2 + 0x2b0) != 0) {
      *(float *)(param_1 + 0x28) = *(float *)(param_1 + 0x28) + FLOAT_803e2ad0;
    }
    if (FLOAT_803e2ad4 <= *(float *)(param_1 + 0x28)) {
      if (FLOAT_803e2ad8 < *(float *)(param_1 + 0x28)) {
        *(float *)(param_1 + 0x28) = FLOAT_803e2ad8;
      }
    }
    else {
      *(float *)(param_1 + 0x28) = FLOAT_803e2ad4;
    }
  }
  FUN_8014cd1c((double)FLOAT_803e2a98,(double)FLOAT_803e2a98,param_1,param_2,0x2d,0);
  return;
}

