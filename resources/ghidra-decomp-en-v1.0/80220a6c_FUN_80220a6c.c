// Function: FUN_80220a6c
// Entry: 80220a6c
// Size: 52 bytes

void FUN_80220a6c(int param_1)

{
  if ((*(byte *)(*(int *)(param_1 + 0xb8) + 4) >> 6 & 1) != 0) {
    FUN_8002cbc4();
  }
  return;
}

