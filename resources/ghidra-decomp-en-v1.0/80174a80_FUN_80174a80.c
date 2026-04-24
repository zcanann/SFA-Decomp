// Function: FUN_80174a80
// Entry: 80174a80
// Size: 380 bytes

void FUN_80174a80(int param_1,int param_2)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x4c);
  *(float *)(param_2 + 0xcc) = FLOAT_803e3580;
  fVar1 = FLOAT_803e3584;
  *(float *)(param_2 + 0xd0) = FLOAT_803e3584;
  *(float *)(param_2 + 0xd4) = fVar1;
  uVar2 = FUN_800221a0(0x19,0x4b);
  *(float *)(param_2 + 0xe4) =
       FLOAT_803e3564 * (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e3578);
  uVar2 = FUN_800221a0(0x28,0x46);
  *(float *)(param_2 + 0xe8) =
       *(float *)(param_2 + 0xe4) /
       (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e3578);
  fVar1 = FLOAT_803e3528;
  *(float *)(param_2 + 0xec) = FLOAT_803e3528;
  *(undefined2 *)(param_2 + 0xac) = *(undefined2 *)(iVar3 + 0x18);
  *(undefined2 *)(param_2 + 0xae) = *(undefined2 *)(iVar3 + 0x1a);
  *(float *)(param_2 + 0xf0) = fVar1;
  *(undefined4 *)(param_2 + 0xbc) = 0;
  FUN_800200e8((int)*(short *)(param_2 + 0xac),0);
  iVar3 = FUN_800394ac(param_1,0,0);
  *(float *)(param_2 + 0xdc) = *(float *)(param_2 + 0xdc) + *(float *)(param_2 + 0xd0);
  if (*(float *)(param_2 + 0xdc) <= FLOAT_803e356c) {
    if (*(float *)(param_2 + 0xdc) < FLOAT_803e3528) {
      *(float *)(param_2 + 0xdc) = FLOAT_803e356c;
    }
  }
  else {
    *(float *)(param_2 + 0xdc) = FLOAT_803e356c;
  }
  *(float *)(param_2 + 0xe0) = *(float *)(param_2 + 0xe0) + *(float *)(param_2 + 0xd4);
  if (*(float *)(param_2 + 0xe0) <= FLOAT_803e356c) {
    if (*(float *)(param_2 + 0xe0) < FLOAT_803e3528) {
      *(float *)(param_2 + 0xe0) = FLOAT_803e356c;
    }
  }
  else {
    *(float *)(param_2 + 0xe0) = FLOAT_803e356c;
  }
  *(undefined *)(iVar3 + 0xc) = 10;
  *(undefined *)(iVar3 + 0xd) = 10;
  *(undefined *)(iVar3 + 0xe) = 10;
  return;
}

