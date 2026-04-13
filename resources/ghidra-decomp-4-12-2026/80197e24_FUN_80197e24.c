// Function: FUN_80197e24
// Entry: 80197e24
// Size: 64 bytes

void FUN_80197e24(int param_1)

{
  uint *puVar1;
  
  puVar1 = *(uint **)(param_1 + 0xb8);
  FUN_8003709c(param_1,0x48);
  if (*puVar1 != 0) {
    FUN_800238c4(*puVar1);
  }
  return;
}

