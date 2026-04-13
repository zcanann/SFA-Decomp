// Function: FUN_802471c4
// Entry: 802471c4
// Size: 236 bytes

void FUN_802471c4(int *param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  FUN_80243e74();
  iVar1 = DAT_800000e4;
  *(undefined2 *)(DAT_800000e4 + 0x2c8) = 4;
  *(int **)(iVar1 + 0x2dc) = param_1;
  for (iVar3 = *param_1; (iVar3 != 0 && (*(int *)(iVar3 + 0x2d0) <= *(int *)(iVar1 + 0x2d0)));
      iVar3 = *(int *)(iVar3 + 0x2e0)) {
  }
  if (iVar3 == 0) {
    iVar3 = param_1[1];
    if (iVar3 == 0) {
      *param_1 = iVar1;
    }
    else {
      *(int *)(iVar3 + 0x2e0) = iVar1;
    }
    *(int *)(iVar1 + 0x2e4) = iVar3;
    *(undefined4 *)(iVar1 + 0x2e0) = 0;
    param_1[1] = iVar1;
  }
  else {
    *(int *)(iVar1 + 0x2e0) = iVar3;
    iVar2 = *(int *)(iVar3 + 0x2e4);
    *(int *)(iVar3 + 0x2e4) = iVar1;
    *(int *)(iVar1 + 0x2e4) = iVar2;
    if (iVar2 == 0) {
      *param_1 = iVar1;
    }
    else {
      *(int *)(iVar2 + 0x2e0) = iVar1;
    }
  }
  DAT_803deb0c = 1;
  FUN_802467dc(0);
  FUN_80243e9c();
  return;
}

