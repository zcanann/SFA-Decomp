// Function: FUN_80276a84
// Entry: 80276a84
// Size: 160 bytes

void FUN_80276a84(int param_1,uint *param_2,uint param_3)

{
  uint *puVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  
  iVar6 = (param_3 & 0xff) * 4;
  uVar3 = *param_2;
  puVar1 = (uint *)(param_1 + iVar6 + 0x188);
  *puVar1 = uVar3 >> 0x10;
  FUN_802836e4((int *)(param_1 + iVar6 + 0x188));
  uVar4 = param_2[1];
  *(uint *)(param_1 + iVar6 + 0x170) = (*param_2 & 0xff00) << 8;
  iVar2 = (char)uVar4 * 0x10000;
  iVar5 = param_1 + iVar6;
  *(int *)(iVar5 + 0x180) = *(int *)(param_1 + iVar6 + 0x170) + iVar2;
  if (*puVar1 == 0) {
    *(int *)(iVar5 + 0x178) = iVar2;
  }
  else {
    *(int *)(iVar5 + 0x178) = iVar2 / (int)(uVar3 >> 0x10);
  }
  *(uint *)(param_1 + 0x114) = *(uint *)(param_1 + 0x114) | 0x2000;
  return;
}

