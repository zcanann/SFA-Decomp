// Function: FUN_800e5184
// Entry: 800e5184
// Size: 316 bytes

int FUN_800e5184(int param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int local_18 [6];
  
  iVar4 = 0;
  iVar2 = *(int *)(param_1 + 0x1c);
  if (((-1 < iVar2) && ((*(byte *)(param_1 + 0x1b) & 1) == 0)) && (iVar2 != param_2)) {
    iVar4 = 1;
    local_18[0] = iVar2;
  }
  iVar3 = *(int *)(param_1 + 0x20);
  iVar2 = iVar4;
  if (((-1 < iVar3) && ((*(byte *)(param_1 + 0x1b) & 2) == 0)) && (iVar3 != param_2)) {
    iVar2 = iVar4 + 1;
    local_18[iVar4] = iVar3;
  }
  iVar3 = *(int *)(param_1 + 0x24);
  iVar4 = iVar2;
  if (((-1 < iVar3) && ((*(byte *)(param_1 + 0x1b) & 4) == 0)) && (iVar3 != param_2)) {
    iVar4 = iVar2 + 1;
    local_18[iVar2] = iVar3;
  }
  iVar3 = *(int *)(param_1 + 0x28);
  iVar2 = iVar4;
  if (((-1 < iVar3) && ((*(byte *)(param_1 + 0x1b) & 8) == 0)) && (iVar3 != param_2)) {
    iVar2 = iVar4 + 1;
    local_18[iVar4] = iVar3;
  }
  if (iVar2 == 0) {
    iVar2 = -1;
  }
  else {
    uVar1 = FUN_80022264(0,iVar2 - 1);
    iVar2 = local_18[uVar1];
  }
  return iVar2;
}

