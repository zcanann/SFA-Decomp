// Function: FUN_80113f9c
// Entry: 80113f9c
// Size: 124 bytes

void FUN_80113f9c(int param_1,wchar_t *param_2,wchar_t *param_3)

{
  if (param_2 == (wchar_t *)0x0) {
    param_2 = u____________8031a0e0;
  }
  if (param_3 == (wchar_t *)0x0) {
    param_3 = u____________8031a0e0;
  }
  FUN_80003494(param_1 + 0x5bc,param_2,(uint)*(byte *)(param_1 + 0x610) << 1);
  FUN_80003494(param_1 + 0x5da,param_3,(uint)*(byte *)(param_1 + 0x610) << 1);
  return;
}

