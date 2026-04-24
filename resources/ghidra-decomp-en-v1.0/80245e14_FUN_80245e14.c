// Function: FUN_80245e14
// Entry: 80245e14
// Size: 104 bytes

void FUN_80245e14(int param_1)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  
  iVar1 = *(int *)(param_1 + 0x2e0);
  piVar2 = *(int **)(param_1 + 0x2dc);
  iVar3 = *(int *)(param_1 + 0x2e4);
  if (iVar1 == 0) {
    piVar2[1] = iVar3;
  }
  else {
    *(int *)(iVar1 + 0x2e4) = iVar3;
  }
  if (iVar3 == 0) {
    *piVar2 = iVar1;
  }
  else {
    *(int *)(iVar3 + 0x2e0) = iVar1;
  }
  if (*piVar2 == 0) {
    DAT_803dde88 = DAT_803dde88 & ~(1 << 0x1f - *(int *)(param_1 + 0x2d0));
  }
  *(undefined4 *)(param_1 + 0x2dc) = 0;
  return;
}

