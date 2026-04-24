// Function: FUN_8014d08c
// Entry: 8014d08c
// Size: 100 bytes

void FUN_8014d08c(double param_1,int param_2,int param_3,undefined param_4,undefined4 param_5,
                 undefined param_6)

{
  *(float *)(param_3 + 0x308) = FLOAT_803e256c / (float)((double)FLOAT_803e2570 * param_1);
  *(undefined *)(param_3 + 0x323) = param_6;
  FUN_80030334((double)FLOAT_803e2574,param_2,param_4,param_5);
  if (*(int *)(param_2 + 0x54) != 0) {
    *(undefined *)(*(int *)(param_2 + 0x54) + 0x70) = 0;
  }
  return;
}

