// Function: FUN_80295ce4
// Entry: 80295ce4
// Size: 16 bytes

byte FUN_80295ce4(int param_1)

{
  return *(byte *)(*(int *)(param_1 + 0xb8) + 0x3f4) >> 6 & 1;
}

