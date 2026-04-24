// Function: FUN_800359cc
// Entry: 800359cc
// Size: 140 bytes

void FUN_800359cc(int param_1,int param_2,int param_3)

{
  int iVar1;
  int *piVar2;
  short sVar3;
  
  iVar1 = (int)*(char *)(*(int *)(param_1 + 0x50) + 0x55);
  if (param_3 < iVar1) {
    if (param_3 < 0) {
      param_3 = 0;
    }
  }
  else {
    param_3 = iVar1 + -1;
  }
  if (*(char *)(param_2 + 0xb0) == param_3) {
    return;
  }
  iVar1 = 0;
  for (sVar3 = 0; sVar3 < 0x32; sVar3 = sVar3 + 1) {
    piVar2 = (int *)(DAT_803dd85c + iVar1);
    if ((*piVar2 != 0) && (piVar2[2] == param_1)) {
      *piVar2 = 0;
    }
    iVar1 = iVar1 + 0x3c;
  }
  *(char *)(param_2 + 0xb0) = (char)param_3;
  return;
}

