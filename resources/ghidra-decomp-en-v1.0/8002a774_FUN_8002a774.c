// Function: FUN_8002a774
// Entry: 8002a774
// Size: 136 bytes

void FUN_8002a774(int param_1,undefined param_2)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  piVar1 = *(int **)(*(int *)(param_1 + 0x7c) + *(char *)(param_1 + 0xad) * 4);
  if ((piVar1 != (int *)0x0) && (iVar4 = *piVar1, iVar4 != 0)) {
    for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(iVar4 + 0xf8); iVar3 = iVar3 + 1) {
      iVar2 = FUN_80028424(iVar4,iVar3);
      *(undefined *)(iVar2 + 0x43) = param_2;
    }
  }
  return;
}

