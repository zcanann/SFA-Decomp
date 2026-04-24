// Function: FUN_80187440
// Entry: 80187440
// Size: 228 bytes

void FUN_80187440(int param_1)

{
  bool bVar1;
  int iVar2;
  int *piVar3;
  int *piVar4;
  
  piVar3 = *(int **)(param_1 + 0xb8);
  bVar1 = false;
  if (*(char *)(*(int *)(param_1 + 0x4c) + 0x19) == '\x01') {
    if (*(char *)(piVar3 + 7) != '\0') {
      if (*piVar3 != 0) {
        (**(code **)(**(int **)(*piVar3 + 0x68) + 0x24))();
      }
      FUN_8001fee8((int)*(short *)(piVar3 + 8));
    }
    bVar1 = true;
  }
  else if (*(char *)((int)piVar3 + 0x1e) < '\0') {
    piVar4 = piVar3;
    for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(piVar3 + 7); iVar2 = iVar2 + 1) {
      FUN_8002cbc4(*piVar4);
      piVar4 = piVar4 + 1;
    }
    bVar1 = true;
  }
  if (bVar1) {
    FUN_8002cbc4(param_1);
  }
  return;
}

