// Function: FUN_80240294
// Entry: 80240294
// Size: 180 bytes

void FUN_80240294(int param_1)

{
  int iVar1;
  int *piVar2;
  
  piVar2 = *(int **)(param_1 + 0xb8);
  if (*piVar2 == 0) {
    iVar1 = FUN_8002e0b4(0x47dd9);
    *piVar2 = iVar1;
  }
  if (*piVar2 != 0) {
    *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(*piVar2 + 0xc);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(*piVar2 + 0x10);
    *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(*piVar2 + 0x14);
  }
  *(undefined *)((int)piVar2 + 0xd) = *(undefined *)(piVar2 + 3);
  if (*(char *)(piVar2 + 3) == '\x01') {
    FUN_80240010(param_1,piVar2);
  }
  return;
}

