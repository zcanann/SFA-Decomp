// Function: FUN_8003393c
// Entry: 8003393c
// Size: 88 bytes

void FUN_8003393c(undefined4 param_1)

{
  int *piVar1;
  int iVar2;
  
  iVar2 = 0;
  for (piVar1 = &DAT_802cada0; (iVar2 < 5 && (*piVar1 != 0)); piVar1 = piVar1 + 1) {
    iVar2 = iVar2 + 1;
  }
  if (iVar2 == 5) {
    DAT_802cada0 = param_1;
    return;
  }
  (&DAT_802cada0)[iVar2] = param_1;
  return;
}

