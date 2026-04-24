// Function: FUN_80297284
// Entry: 80297284
// Size: 24 bytes

void FUN_80297284(int param_1)

{
  *(byte *)(*(int *)(param_1 + 0xb8) + 0x3f2) =
       *(byte *)(*(int *)(param_1 + 0xb8) + 0x3f2) & 0x7f | 0x80;
  return;
}

