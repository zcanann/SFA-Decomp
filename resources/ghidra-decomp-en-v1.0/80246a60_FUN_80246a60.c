// Function: FUN_80246a60
// Entry: 80246a60
// Size: 236 bytes

void FUN_80246a60(int *param_1)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  
  uVar2 = FUN_8024377c();
  iVar1 = DAT_800000e4;
  *(undefined2 *)(DAT_800000e4 + 0x2c8) = 4;
  *(int **)(iVar1 + 0x2dc) = param_1;
  for (iVar4 = *param_1; (iVar4 != 0 && (*(int *)(iVar4 + 0x2d0) <= *(int *)(iVar1 + 0x2d0)));
      iVar4 = *(int *)(iVar4 + 0x2e0)) {
  }
  if (iVar4 == 0) {
    iVar4 = param_1[1];
    if (iVar4 == 0) {
      *param_1 = iVar1;
    }
    else {
      *(int *)(iVar4 + 0x2e0) = iVar1;
    }
    *(int *)(iVar1 + 0x2e4) = iVar4;
    *(undefined4 *)(iVar1 + 0x2e0) = 0;
    param_1[1] = iVar1;
  }
  else {
    *(int *)(iVar1 + 0x2e0) = iVar4;
    iVar3 = *(int *)(iVar4 + 0x2e4);
    *(int *)(iVar4 + 0x2e4) = iVar1;
    *(int *)(iVar1 + 0x2e4) = iVar3;
    if (iVar3 == 0) {
      *param_1 = iVar1;
    }
    else {
      *(int *)(iVar3 + 0x2e0) = iVar1;
    }
  }
  DAT_803dde8c = 1;
  FUN_80246078(0);
  FUN_802437a4(uVar2);
  return;
}

