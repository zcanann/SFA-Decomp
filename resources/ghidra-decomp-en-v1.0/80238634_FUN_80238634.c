// Function: FUN_80238634
// Entry: 80238634
// Size: 72 bytes

void FUN_80238634(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  FUN_80036fa4(param_1,0x4c);
  if (*(int *)(iVar1 + 4) != 0) {
    FUN_8001cb3c(iVar1 + 4);
  }
  FUN_8001467c();
  return;
}

