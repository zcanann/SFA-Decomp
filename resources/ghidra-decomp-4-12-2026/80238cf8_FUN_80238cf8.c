// Function: FUN_80238cf8
// Entry: 80238cf8
// Size: 72 bytes

void FUN_80238cf8(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  FUN_8003709c(param_1,0x4c);
  if (*(int *)(iVar1 + 4) != 0) {
    FUN_8001cc00((uint *)(iVar1 + 4));
  }
  FUN_800146a8();
  return;
}

