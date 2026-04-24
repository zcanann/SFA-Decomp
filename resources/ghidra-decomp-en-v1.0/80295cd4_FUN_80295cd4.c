// Function: FUN_80295cd4
// Entry: 80295cd4
// Size: 16 bytes

byte FUN_80295cd4(int param_1)

{
  return *(byte *)(*(int *)(param_1 + 0xb8) + 0x3f3) >> 3 & 1;
}

