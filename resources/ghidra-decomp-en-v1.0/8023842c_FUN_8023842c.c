// Function: FUN_8023842c
// Entry: 8023842c
// Size: 228 bytes

void FUN_8023842c(int param_1)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  
  piVar3 = *(int **)(param_1 + 0xb8);
  iVar2 = *(int *)(param_1 + 0x4c);
  if (*piVar3 == 0) {
    iVar1 = FUN_8001ffb4((int)*(short *)(iVar2 + 0x20));
    if (iVar1 != 0) {
      *(undefined *)(piVar3 + 1) = *(undefined *)(iVar2 + 0x19);
      *piVar3 = (int)*(short *)(iVar2 + 0x1a);
    }
  }
  else {
    if (*(char *)(piVar3 + 1) != '\0') {
      FUN_800140b4();
    }
    iVar1 = FUN_8001ffb4((int)*(short *)(iVar2 + 0x20));
    if (iVar1 != 0) {
      FUN_800200e8((int)*(short *)(iVar2 + 0x20),0);
      *piVar3 = *piVar3 - iVar1;
      if (*piVar3 < 1) {
        *piVar3 = 0;
        FUN_800200e8((int)*(short *)(iVar2 + 0x1e),1);
        if (*(char *)(piVar3 + 1) != '\0') {
          FUN_800140b4(0xffffffff);
        }
        *(undefined *)(piVar3 + 1) = 0;
      }
    }
  }
  return;
}

