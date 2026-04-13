// Function: FUN_80220120
// Entry: 80220120
// Size: 28 bytes

undefined4 FUN_80220120(int param_1)

{
  *(byte *)(*(int *)(param_1 + 0xb8) + 0x41) = *(byte *)(*(int *)(param_1 + 0xb8) + 0x41) & 0xfb | 4
  ;
  return 1;
}

