// Function: FUN_8029731c
// Entry: 8029731c
// Size: 24 bytes

void FUN_8029731c(int param_1)

{
  *(uint *)(*(int *)(param_1 + 0xb8) + 0x360) =
       *(uint *)(*(int *)(param_1 + 0xb8) + 0x360) & 0xfffffffd;
  return;
}

