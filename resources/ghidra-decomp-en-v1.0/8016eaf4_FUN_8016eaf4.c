// Function: FUN_8016eaf4
// Entry: 8016eaf4
// Size: 84 bytes

void FUN_8016eaf4(int param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  FUN_8016dfe0(param_1,iVar2,param_3,param_2);
  iVar1 = FUN_8002073c();
  if (iVar1 == 0) {
    *(undefined *)(iVar2 + 0xbc) = 0;
  }
  else {
    *(undefined *)(iVar2 + 0xbc) = 1;
  }
  return;
}

