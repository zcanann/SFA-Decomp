// Function: FUN_801c1eac
// Entry: 801c1eac
// Size: 176 bytes

void FUN_801c1eac(int param_1)

{
  bool bVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int local_18 [3];
  
  piVar3 = *(int **)(param_1 + 0xb8);
  FUN_80036fa4(param_1,0x17);
  bVar1 = piVar3[0xb] != 0;
  if ((bVar1) && (bVar1)) {
    FUN_80023800();
  }
  iVar4 = *piVar3;
  if (iVar4 != 0) {
    piVar3 = (int *)FUN_80036f50(0x17,local_18);
    for (iVar2 = 0; iVar2 < local_18[0]; iVar2 = iVar2 + 1) {
      if (*piVar3 == iVar4) {
        (**(code **)(**(int **)(iVar4 + 0x68) + 0x44))(iVar4);
      }
      piVar3 = piVar3 + 1;
    }
  }
  return;
}

