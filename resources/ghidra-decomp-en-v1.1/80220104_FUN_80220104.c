// Function: FUN_80220104
// Entry: 80220104
// Size: 28 bytes

undefined4 FUN_80220104(int param_1)

{
  *(byte *)(*(int *)(param_1 + 0xb8) + 0x41) = *(byte *)(*(int *)(param_1 + 0xb8) + 0x41) & 0xfb;
  return 1;
}

