// Function: FUN_80246c10
// Entry: 80246c10
// Size: 444 bytes

void FUN_80246c10(int param_1)

{
  ushort uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  FUN_80243e74();
  uVar1 = *(ushort *)(param_1 + 0x2c8);
  if (uVar1 == 3) {
LAB_80246d18:
    FUN_80243e9c();
  }
  else {
    if (uVar1 < 3) {
      if (uVar1 == 1) {
        if (*(int *)(param_1 + 0x2cc) < 1) {
          FUN_80246578(param_1);
        }
      }
      else {
        if (uVar1 == 0) goto LAB_80246d18;
        DAT_803deb0c = 1;
      }
    }
    else {
      if (4 < uVar1) goto LAB_80246d18;
      iVar2 = *(int *)(param_1 + 0x2e0);
      iVar3 = *(int *)(param_1 + 0x2e4);
      if (iVar2 == 0) {
        *(int *)(*(int *)(param_1 + 0x2dc) + 4) = iVar3;
      }
      else {
        *(int *)(iVar2 + 0x2e4) = iVar3;
      }
      if (iVar3 == 0) {
        **(int **)(param_1 + 0x2dc) = iVar2;
      }
      else {
        *(int *)(iVar3 + 0x2e0) = iVar2;
      }
      *(undefined4 *)(param_1 + 0x2dc) = 0;
      if ((*(int *)(param_1 + 0x2cc) < 1) && (*(int *)(param_1 + 0x2f0) != 0)) {
        iVar2 = *(int *)(*(int *)(param_1 + 0x2f0) + 8);
        do {
          if ((0 < *(int *)(iVar2 + 0x2cc)) ||
             (iVar3 = FUN_802465e0(iVar2), *(int *)(iVar2 + 0x2d0) == iVar3)) break;
          iVar2 = FUN_8024661c(iVar2,iVar3);
        } while (iVar2 != 0);
      }
    }
    FUN_80242b6c(param_1);
    if ((*(ushort *)(param_1 + 0x2ca) & 1) == 0) {
      *(undefined2 *)(param_1 + 0x2c8) = 8;
    }
    else {
      iVar2 = *(int *)(param_1 + 0x2fc);
      iVar4 = *(int *)(param_1 + 0x300);
      iVar3 = iVar4;
      if (iVar2 != 0) {
        *(int *)(iVar2 + 0x300) = iVar4;
        iVar3 = DAT_800000e0;
      }
      DAT_800000e0 = iVar3;
      if (iVar4 != 0) {
        *(int *)(iVar4 + 0x2fc) = iVar2;
        iVar2 = DAT_800000dc;
      }
      DAT_800000dc = iVar2;
      *(undefined2 *)(param_1 + 0x2c8) = 0;
    }
    FUN_80244bdc(param_1);
    FUN_802472b0((int *)(param_1 + 0x2e8));
    if (DAT_803deb0c != 0) {
      FUN_802467dc(0);
    }
    FUN_80243e9c();
  }
  return;
}

