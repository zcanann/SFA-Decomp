// Function: FUN_8021b738
// Entry: 8021b738
// Size: 352 bytes

int FUN_8021b738(int param_1,int param_2,int param_3)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int local_18 [6];
  
  iVar3 = 0;
  iVar1 = *(int *)(param_1 + 0x1c);
  if (((-1 < iVar1) && ((*(byte *)(param_1 + 0x1b) & 1) == 0)) && (iVar1 != param_2)) {
    iVar3 = 1;
    local_18[0] = iVar1;
  }
  iVar2 = *(int *)(param_1 + 0x20);
  iVar1 = iVar3;
  if (((-1 < iVar2) && ((*(byte *)(param_1 + 0x1b) & 2) == 0)) && (iVar2 != param_2)) {
    iVar1 = iVar3 + 1;
    local_18[iVar3] = iVar2;
  }
  iVar2 = *(int *)(param_1 + 0x24);
  iVar3 = iVar1;
  if (((-1 < iVar2) && ((*(byte *)(param_1 + 0x1b) & 4) == 0)) && (iVar2 != param_2)) {
    iVar3 = iVar1 + 1;
    local_18[iVar1] = iVar2;
  }
  iVar2 = *(int *)(param_1 + 0x28);
  iVar1 = iVar3;
  if (((-1 < iVar2) && ((*(byte *)(param_1 + 0x1b) & 8) == 0)) && (iVar2 != param_2)) {
    iVar1 = iVar3 + 1;
    local_18[iVar3] = iVar2;
  }
  if (iVar1 == 0) {
    iVar1 = -1;
  }
  else {
    if ((param_3 != -1) && (iVar1 + -1 < param_3)) {
      param_3 = iVar1 + -1;
    }
    if (param_3 == -1) {
      param_3 = FUN_800221a0(0,iVar1 + -1);
    }
    iVar1 = local_18[param_3];
  }
  return iVar1;
}

