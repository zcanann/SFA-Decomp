// Function: FUN_8022d6f0
// Entry: 8022d6f0
// Size: 32 bytes

void FUN_8022d6f0(int param_1)

{
  char cVar1;
  
  cVar1 = *(char *)(*(int *)(param_1 + 0xb8) + 0x404);
  if ('\x01' < cVar1) {
    return;
  }
  *(char *)(*(int *)(param_1 + 0xb8) + 0x404) = cVar1 + '\x01';
  return;
}

