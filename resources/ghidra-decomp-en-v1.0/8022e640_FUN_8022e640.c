// Function: FUN_8022e640
// Entry: 8022e640
// Size: 64 bytes

void FUN_8022e640(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  FUN_80036fa4(param_1,2);
  if (*(int *)(iVar1 + 0x14) != 0) {
    FUN_8001f384();
  }
  return;
}

