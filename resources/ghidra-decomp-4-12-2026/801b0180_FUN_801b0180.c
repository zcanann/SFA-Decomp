// Function: FUN_801b0180
// Entry: 801b0180
// Size: 64 bytes

void FUN_801b0180(int param_1)

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

