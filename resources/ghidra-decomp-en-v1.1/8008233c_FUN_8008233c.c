// Function: FUN_8008233c
// Entry: 8008233c
// Size: 92 bytes

void FUN_8008233c(int param_1)

{
  if (*(uint *)(param_1 + 0x94) != 0) {
    FUN_800238c4(*(uint *)(param_1 + 0x94));
    *(undefined4 *)(param_1 + 0x94) = 0;
    *(undefined4 *)(param_1 + 0x98) = 0;
  }
  if (*(uint *)(param_1 + 0x2c) != 0) {
    FUN_800238c4(*(uint *)(param_1 + 0x2c));
    *(undefined4 *)(param_1 + 0x2c) = 0;
  }
  return;
}

