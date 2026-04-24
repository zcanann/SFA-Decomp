// Function: FUN_801e7124
// Entry: 801e7124
// Size: 128 bytes

undefined4 FUN_801e7124(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  iVar1 = FUN_8001ffb4(0xcef);
  if (iVar1 == 0) {
    uVar2 = 0;
  }
  else {
    iVar1 = FUN_8001ffb4(0xad3);
    if (iVar1 == 0) {
      FUN_800200e8(0xad3,1);
      iVar1 = *(int *)(iVar3 + 0x9b4);
      (**(code **)(**(int **)(iVar1 + 0x68) + 0x24))(iVar1,1,2);
    }
    uVar2 = 2;
  }
  return uVar2;
}

