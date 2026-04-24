// Function: FUN_80239460
// Entry: 80239460
// Size: 204 bytes

void FUN_80239460(int param_1)

{
  uint uVar1;
  int *piVar2;
  int iVar3;
  
  piVar2 = *(int **)(param_1 + 0xb8);
  iVar3 = *(int *)(param_1 + 0x4c);
  if ((-1 < *(char *)((int)piVar2 + 9)) &&
     (uVar1 = FUN_80020078((int)*(short *)(iVar3 + 0x1e)), uVar1 != 0)) {
    *(byte *)((int)piVar2 + 9) = *(byte *)((int)piVar2 + 9) & 0x7f | 0x80;
    FUN_80035ff8(param_1);
  }
  if (((-1 < *(char *)((int)piVar2 + 9)) && (*piVar2 == 0)) &&
     (uVar1 = FUN_80020078((int)*(short *)(iVar3 + 0x20)), uVar1 != 0)) {
    FUN_80036018(param_1);
    *piVar2 = (int)*(short *)(iVar3 + 0x1a);
    if (*(char *)(iVar3 + 0x19) != '\x02') {
      FUN_80035a6c(param_1,*(undefined2 *)(iVar3 + 0x1c));
    }
  }
  return;
}

