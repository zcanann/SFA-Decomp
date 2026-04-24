// Function: FUN_80233884
// Entry: 80233884
// Size: 64 bytes

void FUN_80233884(int param_1)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  uVar1 = *(uint *)(iVar2 + 4);
  if (uVar1 != 0) {
    FUN_8001f448(uVar1);
    *(undefined4 *)(iVar2 + 4) = 0;
  }
  return;
}

