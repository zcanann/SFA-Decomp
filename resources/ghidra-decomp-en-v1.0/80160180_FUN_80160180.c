// Function: FUN_80160180
// Entry: 80160180
// Size: 60 bytes

void FUN_80160180(int param_1)

{
  *(undefined4 *)(param_1 + 0xf4) = 0xb4;
  FUN_80035f00();
  *(undefined *)(param_1 + 0x36) = 0xff;
  return;
}

