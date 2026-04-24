// Function: FUN_80246078
// Entry: 80246078
// Size: 512 bytes

int FUN_80246078(int param_1)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  
  if (DAT_803dde90 < 1) {
    iVar2 = FUN_80242308();
    iVar1 = DAT_800000e4;
    if (iVar2 == DAT_800000e4) {
      if (DAT_800000e4 != 0) {
        if (*(short *)(DAT_800000e4 + 0x2c8) == 2) {
          if ((param_1 == 0) &&
             (iVar2 = countLeadingZeros(DAT_803dde88), *(int *)(DAT_800000e4 + 0x2d0) <= iVar2)) {
            return 0;
          }
          *(undefined2 *)(DAT_800000e4 + 0x2c8) = 1;
          *(undefined **)(iVar1 + 0x2dc) = &DAT_803ad438 + *(int *)(iVar1 + 0x2d0) * 8;
          iVar2 = (*(int **)(iVar1 + 0x2dc))[1];
          if (iVar2 == 0) {
            **(int **)(iVar1 + 0x2dc) = iVar1;
          }
          else {
            *(int *)(iVar2 + 0x2e0) = iVar1;
          }
          *(int *)(iVar1 + 0x2e4) = iVar2;
          *(undefined4 *)(iVar1 + 0x2e0) = 0;
          *(int *)(*(int *)(iVar1 + 0x2dc) + 4) = iVar1;
          DAT_803dde88 = DAT_803dde88 | 1 << 0x1f - *(int *)(iVar1 + 0x2d0);
          DAT_803dde8c = 1;
        }
        if (((*(ushort *)(iVar1 + 0x1a2) & 2) == 0) && (iVar1 = FUN_80242314(iVar1), iVar1 != 0)) {
          return 0;
        }
      }
      DAT_800000e4 = 0;
      if (DAT_803dde88 == 0) {
        FUN_802422ac(&DAT_803adb58);
        do {
          FUN_80243790();
          do {
          } while (DAT_803dde88 == 0);
          FUN_8024377c();
        } while (DAT_803dde88 == 0);
        FUN_80242474(&DAT_803adb58);
      }
      DAT_803dde8c = 0;
      iVar4 = countLeadingZeros(DAT_803dde88);
      piVar3 = (int *)(&DAT_803ad438 + iVar4 * 8);
      iVar1 = *piVar3;
      iVar2 = *(int *)(iVar1 + 0x2e0);
      if (iVar2 == 0) {
        *(undefined4 *)(&DAT_803ad43c + iVar4 * 8) = 0;
      }
      else {
        *(undefined4 *)(iVar2 + 0x2e4) = 0;
      }
      *piVar3 = iVar2;
      if (*piVar3 == 0) {
        DAT_803dde88 = DAT_803dde88 & ~(1 << 0x1f - iVar4);
      }
      *(undefined4 *)(iVar1 + 0x2dc) = 0;
      *(undefined2 *)(iVar1 + 0x2c8) = 2;
      DAT_800000e4 = iVar1;
      FUN_802422ac(iVar1);
      FUN_80242394(iVar1);
    }
    else {
      iVar1 = 0;
    }
  }
  else {
    iVar1 = 0;
  }
  return iVar1;
}

