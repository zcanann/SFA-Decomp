// Function: FUN_80246668
// Entry: 80246668
// Size: 648 bytes

int FUN_80246668(int param_1)

{
  ushort uVar1;
  int iVar2;
  undefined4 uVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  
  uVar3 = FUN_8024377c();
  iVar5 = *(int *)(param_1 + 0x2cc);
  *(int *)(param_1 + 0x2cc) = iVar5 + -1;
  if (*(int *)(param_1 + 0x2cc) < 0) {
    *(undefined4 *)(param_1 + 0x2cc) = 0;
  }
  else if (*(int *)(param_1 + 0x2cc) == 0) {
    uVar1 = *(ushort *)(param_1 + 0x2c8);
    if (uVar1 == 4) {
      iVar2 = *(int *)(param_1 + 0x2e0);
      iVar6 = *(int *)(param_1 + 0x2e4);
      if (iVar2 == 0) {
        *(int *)(*(int *)(param_1 + 0x2dc) + 4) = iVar6;
      }
      else {
        *(int *)(iVar2 + 0x2e4) = iVar6;
      }
      if (iVar6 == 0) {
        **(int **)(param_1 + 0x2dc) = iVar2;
      }
      else {
        *(int *)(iVar6 + 0x2e0) = iVar2;
      }
      iVar2 = *(int *)(param_1 + 0x2d4);
      for (piVar4 = *(int **)(param_1 + 0x2f4); piVar4 != (int *)0x0; piVar4 = (int *)piVar4[4]) {
        if ((*piVar4 != 0) && (iVar6 = *(int *)(*piVar4 + 0x2d0), iVar6 < iVar2)) {
          iVar2 = iVar6;
        }
      }
      *(int *)(param_1 + 0x2d0) = iVar2;
      piVar4 = *(int **)(param_1 + 0x2dc);
      for (iVar2 = *piVar4; (iVar2 != 0 && (*(int *)(iVar2 + 0x2d0) <= *(int *)(param_1 + 0x2d0)));
          iVar2 = *(int *)(iVar2 + 0x2e0)) {
      }
      if (iVar2 == 0) {
        iVar2 = piVar4[1];
        if (iVar2 == 0) {
          *piVar4 = param_1;
        }
        else {
          *(int *)(iVar2 + 0x2e0) = param_1;
        }
        *(int *)(param_1 + 0x2e4) = iVar2;
        *(undefined4 *)(param_1 + 0x2e0) = 0;
        *(int *)(*(int *)(param_1 + 0x2dc) + 4) = param_1;
      }
      else {
        *(int *)(param_1 + 0x2e0) = iVar2;
        iVar6 = *(int *)(iVar2 + 0x2e4);
        *(int *)(iVar2 + 0x2e4) = param_1;
        *(int *)(param_1 + 0x2e4) = iVar6;
        if (iVar6 == 0) {
          **(int **)(param_1 + 0x2dc) = param_1;
        }
        else {
          *(int *)(iVar6 + 0x2e0) = param_1;
        }
      }
      if (*(int *)(param_1 + 0x2f0) != 0) {
        iVar2 = *(int *)(*(int *)(param_1 + 0x2f0) + 8);
        do {
          if ((0 < *(int *)(iVar2 + 0x2cc)) ||
             (iVar6 = FUN_80245e7c(iVar2), *(int *)(iVar2 + 0x2d0) == iVar6)) break;
          iVar2 = FUN_80245eb8(iVar2);
        } while (iVar2 != 0);
      }
    }
    else if ((uVar1 < 4) && (uVar1 == 1)) {
      iVar2 = *(int *)(param_1 + 0x2d4);
      for (piVar4 = *(int **)(param_1 + 0x2f4); piVar4 != (int *)0x0; piVar4 = (int *)piVar4[4]) {
        if ((*piVar4 != 0) && (iVar6 = *(int *)(*piVar4 + 0x2d0), iVar6 < iVar2)) {
          iVar2 = iVar6;
        }
      }
      *(int *)(param_1 + 0x2d0) = iVar2;
      *(undefined **)(param_1 + 0x2dc) = &DAT_803ad438 + *(int *)(param_1 + 0x2d0) * 8;
      iVar2 = (*(int **)(param_1 + 0x2dc))[1];
      if (iVar2 == 0) {
        **(int **)(param_1 + 0x2dc) = param_1;
      }
      else {
        *(int *)(iVar2 + 0x2e0) = param_1;
      }
      *(int *)(param_1 + 0x2e4) = iVar2;
      *(undefined4 *)(param_1 + 0x2e0) = 0;
      *(int *)(*(int *)(param_1 + 0x2dc) + 4) = param_1;
      DAT_803dde88 = DAT_803dde88 | 1 << 0x1f - *(int *)(param_1 + 0x2d0);
      DAT_803dde8c = 1;
    }
    if (DAT_803dde8c != 0) {
      FUN_80246078(0);
    }
  }
  FUN_802437a4(uVar3);
  return iVar5;
}

