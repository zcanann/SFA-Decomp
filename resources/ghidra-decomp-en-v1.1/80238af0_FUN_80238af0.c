// Function: FUN_80238af0
// Entry: 80238af0
// Size: 228 bytes

void FUN_80238af0(int param_1)

{
  uint uVar1;
  int iVar2;
  int *piVar3;
  
  piVar3 = *(int **)(param_1 + 0xb8);
  iVar2 = *(int *)(param_1 + 0x4c);
  if (*piVar3 == 0) {
    uVar1 = FUN_80020078((int)*(short *)(iVar2 + 0x20));
    if (uVar1 != 0) {
      *(undefined *)(piVar3 + 1) = *(undefined *)(iVar2 + 0x19);
      *piVar3 = (int)*(short *)(iVar2 + 0x1a);
    }
  }
  else {
    if (*(char *)(piVar3 + 1) != '\0') {
      FUN_800140d4(*piVar3);
    }
    uVar1 = FUN_80020078((int)*(short *)(iVar2 + 0x20));
    if (uVar1 != 0) {
      FUN_800201ac((int)*(short *)(iVar2 + 0x20),0);
      *piVar3 = *piVar3 - uVar1;
      if (*piVar3 < 1) {
        *piVar3 = 0;
        FUN_800201ac((int)*(short *)(iVar2 + 0x1e),1);
        if (*(char *)(piVar3 + 1) != '\0') {
          FUN_800140d4(0xffffffff);
        }
        *(undefined *)(piVar3 + 1) = 0;
      }
    }
  }
  return;
}

