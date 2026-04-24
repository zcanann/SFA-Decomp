// Function: FUN_80220288
// Entry: 80220288
// Size: 48 bytes

void FUN_80220288(int param_1)

{
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  FUN_8021faec();
  return;
}

