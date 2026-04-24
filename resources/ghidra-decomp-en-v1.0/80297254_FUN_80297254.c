// Function: FUN_80297254
// Entry: 80297254
// Size: 24 bytes

void FUN_80297254(int param_1)

{
  *(byte *)(*(int *)(param_1 + 0xb8) + 0x3f2) =
       *(byte *)(*(int *)(param_1 + 0xb8) + 0x3f2) & 0xdf | 0x20;
  return;
}

