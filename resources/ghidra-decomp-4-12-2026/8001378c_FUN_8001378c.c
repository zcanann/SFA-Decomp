// Function: FUN_8001378c
// Entry: 8001378c
// Size: 60 bytes

void FUN_8001378c(int param_1,uint param_2)

{
  FUN_80003494(param_2,*(int *)(param_1 + 0xc) +
                       (int)*(short *)(param_1 + 10) * (int)*(short *)(param_1 + 4),
               (int)*(short *)(param_1 + 4));
  return;
}

