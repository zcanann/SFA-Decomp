// Function: FUN_8021fad0
// Entry: 8021fad0
// Size: 28 bytes

undefined4 FUN_8021fad0(int param_1)

{
  *(byte *)(*(int *)(param_1 + 0xb8) + 0x41) = *(byte *)(*(int *)(param_1 + 0xb8) + 0x41) & 0xfb | 4
  ;
  return 1;
}

