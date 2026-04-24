// Function: FUN_80238ce0
// Entry: 80238ce0
// Size: 16 bytes

byte FUN_80238ce0(int param_1)

{
  return *(byte *)(*(int *)(param_1 + 0xb8) + 0xd) >> 7;
}

