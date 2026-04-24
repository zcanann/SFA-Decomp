// Function: FUN_80245eb8
// Entry: 80245eb8
// Size: 448 bytes

undefined4 FUN_80245eb8(int param_1,undefined4 param_2)

{
  ushort uVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  
  uVar1 = *(ushort *)(param_1 + 0x2c8);
  if (uVar1 != 3) {
    if (uVar1 < 3) {
      if (uVar1 == 1) {
        FUN_80245e14(param_1);
        *(undefined4 *)(param_1 + 0x2d0) = param_2;
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
      else if (uVar1 != 0) {
        DAT_803dde8c = 1;
        *(undefined4 *)(param_1 + 0x2d0) = param_2;
      }
    }
    else if (uVar1 < 5) {
      iVar2 = *(int *)(param_1 + 0x2e0);
      iVar4 = *(int *)(param_1 + 0x2e4);
      if (iVar2 == 0) {
        *(int *)(*(int *)(param_1 + 0x2dc) + 4) = iVar4;
      }
      else {
        *(int *)(iVar2 + 0x2e4) = iVar4;
      }
      if (iVar4 == 0) {
        **(int **)(param_1 + 0x2dc) = iVar2;
      }
      else {
        *(int *)(iVar4 + 0x2e0) = iVar2;
      }
      *(undefined4 *)(param_1 + 0x2d0) = param_2;
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
        iVar4 = *(int *)(iVar2 + 0x2e4);
        *(int *)(iVar2 + 0x2e4) = param_1;
        *(int *)(param_1 + 0x2e4) = iVar4;
        if (iVar4 == 0) {
          **(int **)(param_1 + 0x2dc) = param_1;
        }
        else {
          *(int *)(iVar4 + 0x2e0) = param_1;
        }
      }
      if (*(int *)(param_1 + 0x2f0) != 0) {
        return *(undefined4 *)(*(int *)(param_1 + 0x2f0) + 8);
      }
    }
  }
  return 0;
}

