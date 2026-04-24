// Function: FUN_8021fab4
// Entry: 8021fab4
// Size: 28 bytes

undefined4 FUN_8021fab4(int param_1)

{
  *(byte *)(*(int *)(param_1 + 0xb8) + 0x41) = *(byte *)(*(int *)(param_1 + 0xb8) + 0x41) & 0xfb;
  return 1;
}

