// Function: FUN_80242b6c
// Entry: 80242b6c
// Size: 36 bytes

void FUN_80242b6c(int param_1)

{
  *(undefined2 *)(param_1 + 0x1a0) = 0;
  *(undefined2 *)(param_1 + 0x1a2) = 0;
  if (param_1 == DAT_800000d8) {
    DAT_800000d8 = 0;
  }
  return;
}

