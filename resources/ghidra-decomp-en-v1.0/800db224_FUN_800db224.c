// Function: FUN_800db224
// Entry: 800db224
// Size: 28 bytes

void FUN_800db224(uint param_1,undefined *param_2)

{
  *param_2 = (char)(param_1 & 0xffff);
  param_2[1] = (char)((param_1 & 0xffff) >> 8);
  return;
}

