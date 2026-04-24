// Function: FUN_80246dcc
// Entry: 80246dcc
// Size: 648 bytes

int FUN_80246dcc(int param_1)

{
  ushort uVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  
  FUN_80243e74();
  iVar4 = *(int *)(param_1 + 0x2cc);
  *(int *)(param_1 + 0x2cc) = iVar4 + -1;
  if (*(int *)(param_1 + 0x2cc) < 0) {
    *(undefined4 *)(param_1 + 0x2cc) = 0;
  }
  else if (*(int *)(param_1 + 0x2cc) == 0) {
    uVar1 = *(ushort *)(param_1 + 0x2c8);
    if (uVar1 == 4) {
      iVar2 = *(int *)(param_1 + 0x2e0);
      iVar5 = *(int *)(param_1 + 0x2e4);
      if (iVar2 == 0) {
        *(int *)(*(int *)(param_1 + 0x2dc) + 4) = iVar5;
      }
      else {
        *(int *)(iVar2 + 0x2e4) = iVar5;
      }
      if (iVar5 == 0) {
        **(int **)(param_1 + 0x2dc) = iVar2;
      }
      else {
        *(int *)(iVar5 + 0x2e0) = iVar2;
      }
      iVar2 = *(int *)(param_1 + 0x2d4);
      for (piVar3 = *(int **)(param_1 + 0x2f4); piVar3 != (int *)0x0; piVar3 = (int *)piVar3[4]) {
        if ((*piVar3 != 0) && (iVar5 = *(int *)(*piVar3 + 0x2d0), iVar5 < iVar2)) {
          iVar2 = iVar5;
        }
      }
      *(int *)(param_1 + 0x2d0) = iVar2;
      piVar3 = *(int **)(param_1 + 0x2dc);
      for (iVar2 = *piVar3; (iVar2 != 0 && (*(int *)(iVar2 + 0x2d0) <= *(int *)(param_1 + 0x2d0)));
          iVar2 = *(int *)(iVar2 + 0x2e0)) {
      }
      if (iVar2 == 0) {
        iVar2 = piVar3[1];
        if (iVar2 == 0) {
          *piVar3 = param_1;
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
        iVar5 = *(int *)(iVar2 + 0x2e4);
        *(int *)(iVar2 + 0x2e4) = param_1;
        *(int *)(param_1 + 0x2e4) = iVar5;
        if (iVar5 == 0) {
          **(int **)(param_1 + 0x2dc) = param_1;
        }
        else {
          *(int *)(iVar5 + 0x2e0) = param_1;
        }
      }
      if (*(int *)(param_1 + 0x2f0) != 0) {
        iVar2 = *(int *)(*(int *)(param_1 + 0x2f0) + 8);
        do {
          if ((0 < *(int *)(iVar2 + 0x2cc)) ||
             (iVar5 = FUN_802465e0(iVar2), *(int *)(iVar2 + 0x2d0) == iVar5)) break;
          iVar2 = FUN_8024661c(iVar2,iVar5);
        } while (iVar2 != 0);
      }
    }
    else if ((uVar1 < 4) && (uVar1 == 1)) {
      iVar2 = *(int *)(param_1 + 0x2d4);
      for (piVar3 = *(int **)(param_1 + 0x2f4); piVar3 != (int *)0x0; piVar3 = (int *)piVar3[4]) {
        if ((*piVar3 != 0) && (iVar5 = *(int *)(*piVar3 + 0x2d0), iVar5 < iVar2)) {
          iVar2 = iVar5;
        }
      }
      *(int *)(param_1 + 0x2d0) = iVar2;
      *(undefined **)(param_1 + 0x2dc) = &DAT_803ae098 + *(int *)(param_1 + 0x2d0) * 8;
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
      DAT_803deb08 = DAT_803deb08 | 1 << 0x1f - *(int *)(param_1 + 0x2d0);
      DAT_803deb0c = 1;
    }
    if (DAT_803deb0c != 0) {
      FUN_802467dc(0);
    }
  }
  FUN_80243e9c();
  return iVar4;
}

