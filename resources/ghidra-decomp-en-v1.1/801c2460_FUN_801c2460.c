// Function: FUN_801c2460
// Entry: 801c2460
// Size: 176 bytes

void FUN_801c2460(int param_1)

{
  uint uVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int local_18 [3];
  
  piVar3 = *(int **)(param_1 + 0xb8);
  FUN_8003709c(param_1,0x17);
  uVar1 = piVar3[0xb];
  if ((uVar1 != 0) && (uVar1 != 0)) {
    FUN_800238c4(uVar1);
  }
  iVar4 = *piVar3;
  if (iVar4 != 0) {
    piVar3 = FUN_80037048(0x17,local_18);
    for (iVar2 = 0; iVar2 < local_18[0]; iVar2 = iVar2 + 1) {
      if (*piVar3 == iVar4) {
        (**(code **)(**(int **)(iVar4 + 0x68) + 0x44))(iVar4);
      }
      piVar3 = piVar3 + 1;
    }
  }
  return;
}

