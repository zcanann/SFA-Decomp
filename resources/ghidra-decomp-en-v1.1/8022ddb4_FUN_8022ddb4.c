// Function: FUN_8022ddb4
// Entry: 8022ddb4
// Size: 32 bytes

void FUN_8022ddb4(int param_1)

{
  char cVar1;
  
  cVar1 = *(char *)(*(int *)(param_1 + 0xb8) + 0x404);
  if ('\x01' < cVar1) {
    return;
  }
  *(char *)(*(int *)(param_1 + 0xb8) + 0x404) = cVar1 + '\x01';
  return;
}

