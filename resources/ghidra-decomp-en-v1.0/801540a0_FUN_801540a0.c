// Function: FUN_801540a0
// Entry: 801540a0
// Size: 524 bytes

void FUN_801540a0(int param_1,int param_2)

{
  bool bVar1;
  
  *(float *)(param_2 + 0x32c) = FLOAT_803e294c;
  bVar1 = false;
  FUN_80035df4(param_1,0x18,1,0xffffffff);
  if (*(int *)(param_2 + 0x340) != 0) {
    bVar1 = true;
    *(float *)(param_2 + 0x324) = FLOAT_803e2968;
    *(float *)(param_2 + 0x32c) = FLOAT_803e294c;
    if (*(short *)(param_1 + 0xa0) != 0) {
      FUN_8014d08c((double)FLOAT_803e2958,param_1,param_2,2,0,3);
    }
  }
  if (*(short *)(param_1 + 0xa0) == 3) {
    *(float *)(param_2 + 0x328) = *(float *)(param_2 + 0x328) - FLOAT_803db414;
    if (*(float *)(param_2 + 0x328) <= FLOAT_803e294c) {
      bVar1 = true;
      *(float *)(param_2 + 0x32c) = FLOAT_803e2940;
      *(float *)(param_2 + 0x324) = FLOAT_803e2944;
      FUN_8014d08c((double)FLOAT_803e2948,param_1,param_2,4,0,3);
    }
  }
  else {
    FUN_8014cf7c((double)*(float *)(*(int *)(param_2 + 0x29c) + 0xc),
                 (double)*(float *)(*(int *)(param_2 + 0x29c) + 0x14),param_1,param_2,0x3c,0);
  }
  if (bVar1) {
    *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0x10000;
  }
  else if (*(char *)(param_2 + 0x33a) == '\0') {
    *(undefined *)(param_2 + 0x33a) = 1;
    FUN_8014d08c((double)FLOAT_803e296c,param_1,param_2,1,0,3);
  }
  else if (((*(uint *)(param_2 + 0x2dc) & 0x40000000) != 0) &&
          (FUN_8014d08c((double)FLOAT_803e2970,param_1,param_2,3,0,3),
          FLOAT_803e294c == *(float *)(param_2 + 0x328))) {
    *(float *)(param_2 + 0x328) = FLOAT_803e2974;
    FUN_8014cf7c((double)*(float *)(*(int *)(param_2 + 0x29c) + 0xc),
                 (double)*(float *)(*(int *)(param_2 + 0x29c) + 0x14),param_1,param_2,1,0);
    FUN_8000bb18(param_1,0x25d);
  }
  *(undefined2 *)(param_1 + 2) = *(undefined2 *)(param_2 + 0x19c);
  *(undefined2 *)(param_1 + 4) = *(undefined2 *)(param_2 + 0x19e);
  if (*(char *)(param_2 + 0x33b) != '\0') {
    *(char *)(param_2 + 0x33b) = *(char *)(param_2 + 0x33b) + -1;
  }
  return;
}

