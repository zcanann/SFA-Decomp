// Function: FUN_801e2b5c
// Entry: 801e2b5c
// Size: 392 bytes

void FUN_801e2b5c(int param_1)

{
  int iVar1;
  char in_r8;
  int iVar2;
  byte bVar3;
  undefined auStack40 [6];
  undefined2 local_22;
  float local_20;
  float local_1c;
  float local_18;
  float local_14 [3];
  
  if (in_r8 != '\0') {
    iVar2 = *(int *)(param_1 + 0xb8);
    FUN_8003b8f4((double)FLOAT_803e5830);
    iVar1 = *(int *)(param_1 + 0x30);
    if ((((iVar1 != 0) && (*(short *)(iVar1 + 0x46) == 0x8e)) &&
        (iVar1 = (**(code **)(**(int **)(iVar1 + 0x68) + 0x2c))(), iVar1 != 0)) && (iVar1 != 2)) {
      *(float *)(iVar2 + 8) = *(float *)(iVar2 + 8) - FLOAT_803db414;
      if (*(float *)(iVar2 + 8) <= FLOAT_803e5834) {
        *(float *)(iVar2 + 8) = *(float *)(iVar2 + 8) + FLOAT_803e5838;
      }
      *(float *)(iVar2 + 0xc) = *(float *)(iVar2 + 0xc) - FLOAT_803db414;
      if (*(float *)(iVar2 + 0xc) <= FLOAT_803e5834) {
        *(float *)(iVar2 + 0xc) = *(float *)(iVar2 + 0xc) + FLOAT_803e5830;
      }
      local_20 = FLOAT_803e583c;
      local_22 = 0xc0a;
      FUN_8003842c(param_1,0xd,&local_1c,&local_18,local_14,0);
      local_1c = local_1c - *(float *)(param_1 + 0x18);
      local_18 = local_18 - *(float *)(param_1 + 0x1c);
      local_14[0] = local_14[0] - *(float *)(param_1 + 0x20);
      for (bVar3 = 0; bVar3 < DAT_803db410; bVar3 = bVar3 + 1) {
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x7aa,auStack40,2,0xffffffff,0);
      }
    }
  }
  return;
}

