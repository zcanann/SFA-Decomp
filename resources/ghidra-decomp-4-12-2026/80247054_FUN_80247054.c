// Function: FUN_80247054
// Entry: 80247054
// Size: 368 bytes

int FUN_80247054(int param_1)

{
  ushort uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  FUN_80243e74();
  iVar2 = *(int *)(param_1 + 0x2cc);
  *(int *)(param_1 + 0x2cc) = iVar2 + 1;
  if (iVar2 == 0) {
    uVar1 = *(ushort *)(param_1 + 0x2c8);
    if (uVar1 != 3) {
      if (uVar1 < 3) {
        if (uVar1 == 1) {
          FUN_80246578(param_1);
        }
        else if (uVar1 != 0) {
          DAT_803deb0c = 1;
          *(undefined2 *)(param_1 + 0x2c8) = 1;
        }
      }
      else if (uVar1 < 5) {
        iVar3 = *(int *)(param_1 + 0x2e0);
        iVar4 = *(int *)(param_1 + 0x2e4);
        if (iVar3 == 0) {
          *(int *)(*(int *)(param_1 + 0x2dc) + 4) = iVar4;
        }
        else {
          *(int *)(iVar3 + 0x2e4) = iVar4;
        }
        if (iVar4 == 0) {
          **(int **)(param_1 + 0x2dc) = iVar3;
        }
        else {
          *(int *)(iVar4 + 0x2e0) = iVar3;
        }
        *(undefined4 *)(param_1 + 0x2d0) = 0x20;
        iVar3 = (*(int **)(param_1 + 0x2dc))[1];
        if (iVar3 == 0) {
          **(int **)(param_1 + 0x2dc) = param_1;
        }
        else {
          *(int *)(iVar3 + 0x2e0) = param_1;
        }
        *(int *)(param_1 + 0x2e4) = iVar3;
        *(undefined4 *)(param_1 + 0x2e0) = 0;
        *(int *)(*(int *)(param_1 + 0x2dc) + 4) = param_1;
        if (*(int *)(param_1 + 0x2f0) != 0) {
          iVar3 = *(int *)(*(int *)(param_1 + 0x2f0) + 8);
          do {
            if ((0 < *(int *)(iVar3 + 0x2cc)) ||
               (iVar4 = FUN_802465e0(iVar3), *(int *)(iVar3 + 0x2d0) == iVar4)) break;
            iVar3 = FUN_8024661c(iVar3,iVar4);
          } while (iVar3 != 0);
        }
      }
    }
    if (DAT_803deb0c != 0) {
      FUN_802467dc(0);
    }
  }
  FUN_80243e9c();
  return iVar2;
}

