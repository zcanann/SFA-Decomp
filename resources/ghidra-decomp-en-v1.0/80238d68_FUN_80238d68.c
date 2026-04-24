// Function: FUN_80238d68
// Entry: 80238d68
// Size: 204 bytes

void FUN_80238d68(int param_1)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  
  piVar2 = *(int **)(param_1 + 0xb8);
  iVar3 = *(int *)(param_1 + 0x4c);
  if ((-1 < *(char *)((int)piVar2 + 9)) &&
     (iVar1 = FUN_8001ffb4((int)*(short *)(iVar3 + 0x1e)), iVar1 != 0)) {
    *(byte *)((int)piVar2 + 9) = *(byte *)((int)piVar2 + 9) & 0x7f | 0x80;
    FUN_80035f00(param_1);
  }
  if (((-1 < *(char *)((int)piVar2 + 9)) && (*piVar2 == 0)) &&
     (iVar1 = FUN_8001ffb4((int)*(short *)(iVar3 + 0x20)), iVar1 != 0)) {
    FUN_80035f20(param_1);
    *piVar2 = (int)*(short *)(iVar3 + 0x1a);
    if (*(char *)(iVar3 + 0x19) != '\x02') {
      FUN_80035974(param_1,(int)*(short *)(iVar3 + 0x1c));
    }
  }
  return;
}

