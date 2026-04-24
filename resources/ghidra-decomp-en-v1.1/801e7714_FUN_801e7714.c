// Function: FUN_801e7714
// Entry: 801e7714
// Size: 128 bytes

undefined4 FUN_801e7714(int param_1)

{
  uint uVar1;
  undefined4 uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  uVar1 = FUN_80020078(0xcef);
  if (uVar1 == 0) {
    uVar2 = 0;
  }
  else {
    uVar1 = FUN_80020078(0xad3);
    if (uVar1 == 0) {
      FUN_800201ac(0xad3,1);
      iVar3 = *(int *)(iVar3 + 0x9b4);
      (**(code **)(**(int **)(iVar3 + 0x68) + 0x24))(iVar3,1,2);
    }
    uVar2 = 2;
  }
  return uVar2;
}

