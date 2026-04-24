// Function: FUN_80028500
// Entry: 80028500
// Size: 76 bytes

void FUN_80028500(int param_1)

{
  if (*(uint *)(param_1 + 0x58) == 0) {
    *(undefined4 *)(param_1 + 0x38) = 0;
  }
  else {
    FUN_800238c4(*(uint *)(param_1 + 0x58));
    *(undefined4 *)(param_1 + 0x58) = 0;
  }
  return;
}

