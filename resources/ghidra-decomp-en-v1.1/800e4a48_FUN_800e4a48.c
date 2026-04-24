// Function: FUN_800e4a48
// Entry: 800e4a48
// Size: 568 bytes

void FUN_800e4a48(int param_1,int *param_2)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  
  *param_2 = -1;
  param_2[1] = -1;
  param_2[2] = -1;
  param_2[3] = -1;
  if (param_1 == 0) {
    return;
  }
  param_2[1] = *(int *)(param_1 + 0x14);
  iVar3 = *(int *)(param_1 + 0x1c);
  if (iVar3 != -1) {
    bVar1 = (*(byte *)(param_1 + 0x1b) & 1) == 0;
    if (bVar1) {
      if (bVar1) {
        param_2[2] = iVar3;
      }
    }
    else {
      *param_2 = iVar3;
    }
  }
  iVar3 = *(int *)(param_1 + 0x20);
  if (iVar3 != -1) {
    bVar1 = (*(byte *)(param_1 + 0x1b) & 2) == 0;
    if (bVar1) {
      if (bVar1) {
        param_2[2] = iVar3;
      }
    }
    else {
      *param_2 = iVar3;
    }
  }
  iVar3 = *(int *)(param_1 + 0x24);
  if (iVar3 != -1) {
    bVar1 = (*(byte *)(param_1 + 0x1b) & 4) == 0;
    if (bVar1) {
      if (bVar1) {
        param_2[2] = iVar3;
      }
    }
    else {
      *param_2 = iVar3;
    }
  }
  iVar3 = *(int *)(param_1 + 0x28);
  if (iVar3 != -1) {
    bVar1 = (*(byte *)(param_1 + 0x1b) & 8) == 0;
    if (bVar1) {
      if (bVar1) {
        param_2[2] = iVar3;
      }
    }
    else {
      *param_2 = iVar3;
    }
  }
  uVar5 = param_2[2];
  if ((int)uVar5 < 0) {
    return;
  }
  if ((int)uVar5 < 0) {
    iVar6 = 0;
  }
  else {
    iVar4 = DAT_803de0f0 + -1;
    iVar3 = 0;
    while (iVar3 <= iVar4) {
      iVar2 = iVar4 + iVar3 >> 1;
      iVar6 = (&DAT_803a2448)[iVar2];
      if (*(uint *)(iVar6 + 0x14) < uVar5) {
        iVar3 = iVar2 + 1;
      }
      else {
        if (*(uint *)(iVar6 + 0x14) <= uVar5) goto LAB_800e4bc4;
        iVar4 = iVar2 + -1;
      }
    }
    iVar6 = 0;
  }
LAB_800e4bc4:
  if (iVar6 == 0) {
    return;
  }
  if ((*(int *)(iVar6 + 0x1c) != -1) && ((*(byte *)(iVar6 + 0x1b) & 1) == 0)) {
    param_2[3] = *(int *)(iVar6 + 0x1c);
  }
  if ((*(int *)(iVar6 + 0x20) != -1) && ((*(byte *)(iVar6 + 0x1b) & 2) == 0)) {
    param_2[3] = *(int *)(iVar6 + 0x20);
  }
  if ((*(int *)(iVar6 + 0x24) != -1) && ((*(byte *)(iVar6 + 0x1b) & 4) == 0)) {
    param_2[3] = *(int *)(iVar6 + 0x24);
  }
  if (*(int *)(iVar6 + 0x28) == -1) {
    return;
  }
  if ((*(byte *)(iVar6 + 0x1b) & 8) != 0) {
    return;
  }
  param_2[3] = *(int *)(iVar6 + 0x28);
  return;
}

