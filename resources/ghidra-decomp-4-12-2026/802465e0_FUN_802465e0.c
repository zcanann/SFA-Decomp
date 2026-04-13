// Function: FUN_802465e0
// Entry: 802465e0
// Size: 60 bytes

int FUN_802465e0(int param_1)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  
  iVar2 = *(int *)(param_1 + 0x2d4);
  for (piVar3 = *(int **)(param_1 + 0x2f4); piVar3 != (int *)0x0; piVar3 = (int *)piVar3[4]) {
    if ((*piVar3 != 0) && (iVar1 = *(int *)(*piVar3 + 0x2d0), iVar1 < iVar2)) {
      iVar2 = iVar1;
    }
  }
  return iVar2;
}

