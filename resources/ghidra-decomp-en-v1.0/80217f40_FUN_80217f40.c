// Function: FUN_80217f40
// Entry: 80217f40
// Size: 64 bytes

void FUN_80217f40(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(byte *)(iVar1 + 5) = *(byte *)(iVar1 + 5) | 1;
  if (*(char *)(iVar1 + 4) == '\x01') {
    FUN_8002cbc4();
  }
  return;
}

