// Function: FUN_8023861c
// Entry: 8023861c
// Size: 16 bytes

byte FUN_8023861c(int param_1)

{
  return *(byte *)(*(int *)(param_1 + 0xb8) + 0xd) >> 7;
}

