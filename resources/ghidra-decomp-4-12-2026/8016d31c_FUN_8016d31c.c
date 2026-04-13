// Function: FUN_8016d31c
// Entry: 8016d31c
// Size: 64 bytes

void FUN_8016d31c(int param_1)

{
  byte bVar1;
  
  bVar1 = **(byte **)(param_1 + 0xb8);
  if ((char)bVar1 < '\0') {
    **(byte **)(param_1 + 0xb8) = bVar1 & 0x7f;
    FUN_800551ec();
  }
  return;
}

