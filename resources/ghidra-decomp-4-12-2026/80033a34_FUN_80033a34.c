// Function: FUN_80033a34
// Entry: 80033a34
// Size: 88 bytes

void FUN_80033a34(undefined4 param_1)

{
  int *piVar1;
  int iVar2;
  
  iVar2 = 0;
  for (piVar1 = &DAT_802cb978; (iVar2 < 5 && (*piVar1 != 0)); piVar1 = piVar1 + 1) {
    iVar2 = iVar2 + 1;
  }
  if (iVar2 == 5) {
    DAT_802cb978 = param_1;
    return;
  }
  (&DAT_802cb978)[iVar2] = param_1;
  return;
}

