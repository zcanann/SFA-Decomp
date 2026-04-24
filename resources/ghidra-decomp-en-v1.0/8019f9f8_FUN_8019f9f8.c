// Function: FUN_8019f9f8
// Entry: 8019f9f8
// Size: 72 bytes

void FUN_8019f9f8(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  iVar1 = FUN_8003687c(param_1,0,0,0);
  if (iVar1 == 0x13) {
    *(undefined *)(iVar2 + 0x37) = 7;
  }
  return;
}

