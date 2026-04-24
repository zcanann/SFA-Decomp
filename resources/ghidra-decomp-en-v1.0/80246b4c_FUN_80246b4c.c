// Function: FUN_80246b4c
// Entry: 80246b4c
// Size: 260 bytes

void FUN_80246b4c(int *param_1)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  
  uVar1 = FUN_8024377c();
  while (iVar3 = *param_1, iVar3 != 0) {
    iVar2 = *(int *)(iVar3 + 0x2e0);
    if (iVar2 == 0) {
      param_1[1] = 0;
    }
    else {
      *(undefined4 *)(iVar2 + 0x2e4) = 0;
    }
    *param_1 = iVar2;
    *(undefined2 *)(iVar3 + 0x2c8) = 1;
    if (*(int *)(iVar3 + 0x2cc) < 1) {
      *(undefined **)(iVar3 + 0x2dc) = &DAT_803ad438 + *(int *)(iVar3 + 0x2d0) * 8;
      iVar2 = (*(int **)(iVar3 + 0x2dc))[1];
      if (iVar2 == 0) {
        **(int **)(iVar3 + 0x2dc) = iVar3;
      }
      else {
        *(int *)(iVar2 + 0x2e0) = iVar3;
      }
      *(int *)(iVar3 + 0x2e4) = iVar2;
      *(undefined4 *)(iVar3 + 0x2e0) = 0;
      *(int *)(*(int *)(iVar3 + 0x2dc) + 4) = iVar3;
      DAT_803dde88 = DAT_803dde88 | 1 << 0x1f - *(int *)(iVar3 + 0x2d0);
      DAT_803dde8c = 1;
    }
  }
  if (DAT_803dde8c != 0) {
    FUN_80246078(0);
  }
  FUN_802437a4(uVar1);
  return;
}

