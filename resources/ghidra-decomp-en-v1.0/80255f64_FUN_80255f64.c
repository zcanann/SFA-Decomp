// Function: FUN_80255f64
// Entry: 80255f64
// Size: 112 bytes

void FUN_80255f64(int param_1,int param_2,int param_3)

{
  FUN_8024377c();
  *(int *)(param_1 + 0x14) = param_2;
  *(int *)(param_1 + 0x18) = param_3;
  *(int *)(param_1 + 0x1c) = param_3 - param_2;
  if (*(int *)(param_1 + 0x1c) < 0) {
    *(int *)(param_1 + 0x1c) = *(int *)(param_1 + 0x1c) + *(int *)(param_1 + 8);
  }
  FUN_802437a4();
  return;
}

