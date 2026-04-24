// Function: FUN_80296bbc
// Entry: 80296bbc
// Size: 24 bytes

void FUN_80296bbc(int param_1)

{
  *(uint *)(*(int *)(param_1 + 0xb8) + 0x360) =
       *(uint *)(*(int *)(param_1 + 0xb8) + 0x360) & 0xfffffffd;
  return;
}

