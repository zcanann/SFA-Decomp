// Function: FUN_8020b3b0
// Entry: 8020b3b0
// Size: 120 bytes

void FUN_8020b3b0(int param_1)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  FUN_8003709c(param_1,0x45);
  if (*(int *)(param_1 + 200) != 0) {
    FUN_80037da8(param_1,*(int *)(param_1 + 200));
  }
  uVar1 = *(uint *)(iVar2 + 0x160);
  if (uVar1 != 0) {
    FUN_8001f448(uVar1);
  }
  FUN_8000a538((int *)0x26,0);
  FUN_8000a538((int *)0x96,0);
  return;
}

