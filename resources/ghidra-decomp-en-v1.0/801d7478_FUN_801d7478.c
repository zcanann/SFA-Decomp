// Function: FUN_801d7478
// Entry: 801d7478
// Size: 76 bytes

void FUN_801d7478(int param_1,int param_2)

{
  int iVar1;
  int *piVar2;
  
  piVar2 = *(int **)(param_1 + 0xb8);
  iVar1 = *piVar2;
  if ((iVar1 != 0) && (param_2 == 0)) {
    FUN_80037cb0(param_1,iVar1);
    FUN_8002cbc4(*piVar2);
  }
  return;
}

