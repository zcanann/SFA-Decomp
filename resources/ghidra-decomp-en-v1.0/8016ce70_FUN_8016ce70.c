// Function: FUN_8016ce70
// Entry: 8016ce70
// Size: 64 bytes

void FUN_8016ce70(int param_1)

{
  byte bVar1;
  
  bVar1 = **(byte **)(param_1 + 0xb8);
  if ((char)bVar1 < '\0') {
    **(byte **)(param_1 + 0xb8) = bVar1 & 0x7f;
    FUN_80055070();
  }
  return;
}

