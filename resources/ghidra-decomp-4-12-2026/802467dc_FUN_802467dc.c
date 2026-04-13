// Function: FUN_802467dc
// Entry: 802467dc
// Size: 512 bytes

uint FUN_802467dc(int param_1)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  uint *puVar4;
  
  if (DAT_803deb10 < 1) {
    uVar2 = FUN_80242a00();
    uVar1 = DAT_800000e4;
    if (uVar2 == DAT_800000e4) {
      if (DAT_800000e4 != 0) {
        if (*(short *)(DAT_800000e4 + 0x2c8) == 2) {
          if ((param_1 == 0) &&
             (iVar3 = countLeadingZeros(DAT_803deb08), *(int *)(DAT_800000e4 + 0x2d0) <= iVar3)) {
            return 0;
          }
          *(undefined2 *)(DAT_800000e4 + 0x2c8) = 1;
          *(undefined **)(uVar1 + 0x2dc) = &DAT_803ae098 + *(int *)(uVar1 + 0x2d0) * 8;
          uVar2 = (*(uint **)(uVar1 + 0x2dc))[1];
          if (uVar2 == 0) {
            **(uint **)(uVar1 + 0x2dc) = uVar1;
          }
          else {
            *(uint *)(uVar2 + 0x2e0) = uVar1;
          }
          *(uint *)(uVar1 + 0x2e4) = uVar2;
          *(undefined4 *)(uVar1 + 0x2e0) = 0;
          *(uint *)(*(int *)(uVar1 + 0x2dc) + 4) = uVar1;
          DAT_803deb08 = DAT_803deb08 | 1 << 0x1f - *(int *)(uVar1 + 0x2d0);
          DAT_803deb0c = 1;
        }
        if (((*(ushort *)(uVar1 + 0x1a2) & 2) == 0) && (iVar3 = FUN_80242a0c(uVar1), iVar3 != 0)) {
          return 0;
        }
      }
      DAT_800000e4 = 0;
      if (DAT_803deb08 == 0) {
        FUN_802429a4(0x803ae7b8);
        do {
          FUN_80243e88();
          do {
          } while (DAT_803deb08 == 0);
          FUN_80243e74();
        } while (DAT_803deb08 == 0);
        FUN_80242b6c(-0x7fc51848);
      }
      DAT_803deb0c = 0;
      iVar3 = countLeadingZeros(DAT_803deb08);
      puVar4 = (uint *)(&DAT_803ae098 + iVar3 * 8);
      uVar1 = *puVar4;
      uVar2 = *(uint *)(uVar1 + 0x2e0);
      if (uVar2 == 0) {
        *(undefined4 *)(&DAT_803ae09c + iVar3 * 8) = 0;
      }
      else {
        *(undefined4 *)(uVar2 + 0x2e4) = 0;
      }
      *puVar4 = uVar2;
      if (*puVar4 == 0) {
        DAT_803deb08 = DAT_803deb08 & ~(1 << 0x1f - iVar3);
      }
      *(undefined4 *)(uVar1 + 0x2dc) = 0;
      *(undefined2 *)(uVar1 + 0x2c8) = 2;
      DAT_800000e4 = uVar1;
      FUN_802429a4(uVar1);
      FUN_80242a8c(uVar1);
    }
    else {
      uVar1 = 0;
    }
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}

