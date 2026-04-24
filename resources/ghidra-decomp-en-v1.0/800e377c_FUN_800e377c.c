// Function: FUN_800e377c
// Entry: 800e377c
// Size: 2988 bytes

void FUN_800e377c(undefined4 param_1,undefined4 param_2,int param_3,int param_4,int param_5)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  double dVar11;
  undefined8 uVar12;
  uint local_a8 [4];
  uint local_98 [4];
  undefined4 local_88;
  uint uStack132;
  undefined4 local_80;
  uint uStack124;
  undefined4 local_78;
  uint uStack116;
  undefined4 local_70;
  uint uStack108;
  undefined4 local_68;
  uint uStack100;
  undefined4 local_60;
  uint uStack92;
  undefined4 local_58;
  uint uStack84;
  undefined4 local_50;
  uint uStack76;
  undefined4 local_48;
  uint uStack68;
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  undefined4 local_30;
  uint uStack44;
  
  uVar12 = FUN_802860c8();
  iVar3 = (int)((ulonglong)uVar12 >> 0x20);
  iVar2 = (int)uVar12;
  bVar1 = false;
  if ((*(int *)(iVar3 + 0x1c) == -1) || ((*(byte *)(iVar3 + 0x1b) & 1) != 0)) {
    if ((*(int *)(iVar3 + 0x20) == -1) || ((*(byte *)(iVar3 + 0x1b) & 2) != 0)) {
      if ((*(int *)(iVar3 + 0x24) == -1) || ((*(byte *)(iVar3 + 0x1b) & 4) != 0)) {
        if ((*(int *)(iVar3 + 0x28) == -1) || ((*(byte *)(iVar3 + 0x1b) & 8) != 0)) {
          bVar1 = true;
        }
        else {
          bVar1 = false;
        }
      }
      else {
        bVar1 = false;
      }
    }
    else {
      bVar1 = false;
    }
  }
  iVar10 = 0;
  iVar9 = 0;
  iVar8 = 0;
  if (bVar1) {
    while (iVar8 = iVar3, iVar8 != 0) {
      bVar1 = false;
      if ((*(int *)(iVar8 + 0x1c) == -1) || ((*(byte *)(iVar8 + 0x1b) & 1) == 0)) {
        if ((*(int *)(iVar8 + 0x20) == -1) || ((*(byte *)(iVar8 + 0x1b) & 2) == 0)) {
          if ((*(int *)(iVar8 + 0x24) == -1) || ((*(byte *)(iVar8 + 0x1b) & 4) == 0)) {
            if ((*(int *)(iVar8 + 0x28) == -1) || ((*(byte *)(iVar8 + 0x1b) & 8) == 0)) {
              bVar1 = true;
            }
            else {
              bVar1 = false;
            }
          }
          else {
            bVar1 = false;
          }
        }
        else {
          bVar1 = false;
        }
      }
      if (bVar1) break;
      iVar3 = 0;
      uVar5 = *(uint *)(iVar8 + 0x1c);
      if (((-1 < (int)uVar5) && ((*(byte *)(iVar8 + 0x1b) & 1) != 0)) && (uVar5 != 0)) {
        iVar3 = 1;
        local_a8[0] = uVar5;
      }
      uVar5 = *(uint *)(iVar8 + 0x20);
      iVar4 = iVar3;
      if (((-1 < (int)uVar5) && ((*(byte *)(iVar8 + 0x1b) & 2) != 0)) && (uVar5 != 0)) {
        iVar4 = iVar3 + 1;
        local_a8[iVar3] = uVar5;
      }
      uVar5 = *(uint *)(iVar8 + 0x24);
      iVar3 = iVar4;
      if (((-1 < (int)uVar5) && ((*(byte *)(iVar8 + 0x1b) & 4) != 0)) && (uVar5 != 0)) {
        iVar3 = iVar4 + 1;
        local_a8[iVar4] = uVar5;
      }
      uVar5 = *(uint *)(iVar8 + 0x28);
      iVar4 = iVar3;
      if (((-1 < (int)uVar5) && ((*(byte *)(iVar8 + 0x1b) & 8) != 0)) && (uVar5 != 0)) {
        iVar4 = iVar3 + 1;
        local_a8[iVar3] = uVar5;
      }
      if (iVar4 == 0) {
        uVar5 = 0xffffffff;
      }
      else {
        iVar3 = FUN_800221a0(0,iVar4 + -1);
        uVar5 = local_a8[iVar3];
      }
      if ((int)uVar5 < 0) {
        iVar3 = 0;
      }
      else {
        iVar7 = DAT_803dd478 + -1;
        iVar4 = 0;
        while (iVar4 <= iVar7) {
          iVar6 = iVar7 + iVar4 >> 1;
          iVar3 = (&DAT_803a17e8)[iVar6];
          if (*(uint *)(iVar3 + 0x14) < uVar5) {
            iVar4 = iVar6 + 1;
          }
          else {
            if (*(uint *)(iVar3 + 0x14) <= uVar5) goto LAB_800e3f60;
            iVar7 = iVar6 + -1;
          }
        }
        iVar3 = 0;
      }
LAB_800e3f60:
      if (iVar3 != 0) {
        if (param_5 != 0) {
          *(undefined *)(param_5 + (iVar10 >> 2)) = *(undefined *)(iVar8 + 0x19);
        }
        *(undefined4 *)(iVar2 + iVar9) = *(undefined4 *)(iVar8 + 8);
        *(undefined4 *)(param_3 + iVar9) = *(undefined4 *)(iVar8 + 0xc);
        iVar4 = iVar9 + 4;
        *(undefined4 *)(param_4 + iVar9) = *(undefined4 *)(iVar8 + 0x10);
        *(undefined4 *)(iVar2 + iVar4) = *(undefined4 *)(iVar3 + 8);
        *(undefined4 *)(param_3 + iVar4) = *(undefined4 *)(iVar3 + 0xc);
        *(undefined4 *)(param_4 + iVar4) = *(undefined4 *)(iVar3 + 0x10);
        uStack44 = (int)*(char *)(iVar8 + 0x2c) << 8 ^ 0x80000000;
        local_30 = 0x43300000;
        dVar11 = (double)FUN_80293e80((double)((FLOAT_803e0614 *
                                               (float)((double)CONCAT44(0x43300000,uStack44) -
                                                      DOUBLE_803e0620)) / FLOAT_803e0618));
        uStack52 = (uint)*(byte *)(iVar8 + 0x2e);
        local_38 = 0x43300000;
        *(float *)(iVar2 + iVar9 + 8) =
             FLOAT_803e0610 *
             (float)((double)(float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e0628) *
                    dVar11);
        uStack60 = (int)*(char *)(iVar8 + 0x2d) << 8 ^ 0x80000000;
        local_40 = 0x43300000;
        dVar11 = (double)FUN_80293e80((double)((FLOAT_803e0614 *
                                               (float)((double)CONCAT44(0x43300000,uStack60) -
                                                      DOUBLE_803e0620)) / FLOAT_803e0618));
        uStack68 = (uint)*(byte *)(iVar8 + 0x2e);
        local_48 = 0x43300000;
        *(float *)(param_3 + iVar9 + 8) =
             FLOAT_803e0610 *
             (float)((double)(float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e0628) *
                    dVar11);
        uStack76 = (int)*(char *)(iVar8 + 0x2c) << 8 ^ 0x80000000;
        local_50 = 0x43300000;
        dVar11 = (double)FUN_80294204((double)((FLOAT_803e0614 *
                                               (float)((double)CONCAT44(0x43300000,uStack76) -
                                                      DOUBLE_803e0620)) / FLOAT_803e0618));
        uStack84 = (uint)*(byte *)(iVar8 + 0x2e);
        local_58 = 0x43300000;
        iVar8 = iVar10 + 3;
        *(float *)(param_4 + (iVar10 + 2) * 4) =
             FLOAT_803e0610 *
             (float)((double)(float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803e0628) *
                    dVar11);
        uStack92 = (int)*(char *)(iVar3 + 0x2c) << 8 ^ 0x80000000;
        local_60 = 0x43300000;
        dVar11 = (double)FUN_80293e80((double)((FLOAT_803e0614 *
                                               (float)((double)CONCAT44(0x43300000,uStack92) -
                                                      DOUBLE_803e0620)) / FLOAT_803e0618));
        uStack100 = (uint)*(byte *)(iVar3 + 0x2e);
        local_68 = 0x43300000;
        *(float *)(iVar2 + iVar9 + 0xc) =
             FLOAT_803e0610 *
             (float)((double)(float)((double)CONCAT44(0x43300000,uStack100) - DOUBLE_803e0628) *
                    dVar11);
        uStack108 = (int)*(char *)(iVar3 + 0x2d) << 8 ^ 0x80000000;
        local_70 = 0x43300000;
        dVar11 = (double)FUN_80293e80((double)((FLOAT_803e0614 *
                                               (float)((double)CONCAT44(0x43300000,uStack108) -
                                                      DOUBLE_803e0620)) / FLOAT_803e0618));
        uStack116 = (uint)*(byte *)(iVar3 + 0x2e);
        local_78 = 0x43300000;
        *(float *)(param_3 + iVar9 + 0xc) =
             FLOAT_803e0610 *
             (float)((double)(float)((double)CONCAT44(0x43300000,uStack116) - DOUBLE_803e0628) *
                    dVar11);
        uStack124 = (int)*(char *)(iVar3 + 0x2c) << 8 ^ 0x80000000;
        local_80 = 0x43300000;
        dVar11 = (double)FUN_80294204((double)((FLOAT_803e0614 *
                                               (float)((double)CONCAT44(0x43300000,uStack124) -
                                                      DOUBLE_803e0620)) / FLOAT_803e0618));
        uStack132 = (uint)*(byte *)(iVar3 + 0x2e);
        local_88 = 0x43300000;
        iVar10 = iVar10 + 4;
        iVar9 = iVar9 + 0x10;
        *(float *)(param_4 + iVar8 * 4) =
             FLOAT_803e0610 *
             (float)((double)(float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803e0628) *
                    dVar11);
      }
    }
  }
  else {
    while (iVar9 = iVar3, iVar9 != 0) {
      bVar1 = false;
      if ((*(int *)(iVar9 + 0x1c) == -1) || ((*(byte *)(iVar9 + 0x1b) & 1) != 0)) {
        if ((*(int *)(iVar9 + 0x20) == -1) || ((*(byte *)(iVar9 + 0x1b) & 2) != 0)) {
          if ((*(int *)(iVar9 + 0x24) == -1) || ((*(byte *)(iVar9 + 0x1b) & 4) != 0)) {
            if ((*(int *)(iVar9 + 0x28) == -1) || ((*(byte *)(iVar9 + 0x1b) & 8) != 0)) {
              bVar1 = true;
            }
            else {
              bVar1 = false;
            }
          }
          else {
            bVar1 = false;
          }
        }
        else {
          bVar1 = false;
        }
      }
      if (bVar1) break;
      iVar3 = 0;
      uVar5 = *(uint *)(iVar9 + 0x1c);
      if (((-1 < (int)uVar5) && ((*(byte *)(iVar9 + 0x1b) & 1) == 0)) && (uVar5 != 0)) {
        iVar3 = 1;
        local_98[0] = uVar5;
      }
      uVar5 = *(uint *)(iVar9 + 0x20);
      iVar4 = iVar3;
      if (((-1 < (int)uVar5) && ((*(byte *)(iVar9 + 0x1b) & 2) == 0)) && (uVar5 != 0)) {
        iVar4 = iVar3 + 1;
        local_98[iVar3] = uVar5;
      }
      uVar5 = *(uint *)(iVar9 + 0x24);
      iVar3 = iVar4;
      if (((-1 < (int)uVar5) && ((*(byte *)(iVar9 + 0x1b) & 4) == 0)) && (uVar5 != 0)) {
        iVar3 = iVar4 + 1;
        local_98[iVar4] = uVar5;
      }
      uVar5 = *(uint *)(iVar9 + 0x28);
      iVar4 = iVar3;
      if (((-1 < (int)uVar5) && ((*(byte *)(iVar9 + 0x1b) & 8) == 0)) && (uVar5 != 0)) {
        iVar4 = iVar3 + 1;
        local_98[iVar3] = uVar5;
      }
      if (iVar4 == 0) {
        uVar5 = 0xffffffff;
      }
      else {
        iVar3 = FUN_800221a0(0,iVar4 + -1);
        uVar5 = local_98[iVar3];
      }
      if ((int)uVar5 < 0) {
        iVar3 = 0;
      }
      else {
        iVar7 = DAT_803dd478 + -1;
        iVar4 = 0;
        while (iVar4 <= iVar7) {
          iVar6 = iVar7 + iVar4 >> 1;
          iVar3 = (&DAT_803a17e8)[iVar6];
          if (*(uint *)(iVar3 + 0x14) < uVar5) {
            iVar4 = iVar6 + 1;
          }
          else {
            if (*(uint *)(iVar3 + 0x14) <= uVar5) goto LAB_800e3a1c;
            iVar7 = iVar6 + -1;
          }
        }
        iVar3 = 0;
      }
LAB_800e3a1c:
      if (iVar3 != 0) {
        if (param_5 != 0) {
          *(undefined *)(param_5 + (iVar10 >> 2)) = *(undefined *)(iVar9 + 0x19);
        }
        *(undefined4 *)(iVar2 + iVar8) = *(undefined4 *)(iVar9 + 8);
        *(undefined4 *)(param_3 + iVar8) = *(undefined4 *)(iVar9 + 0xc);
        iVar4 = iVar8 + 4;
        *(undefined4 *)(param_4 + iVar8) = *(undefined4 *)(iVar9 + 0x10);
        *(undefined4 *)(iVar2 + iVar4) = *(undefined4 *)(iVar3 + 8);
        *(undefined4 *)(param_3 + iVar4) = *(undefined4 *)(iVar3 + 0xc);
        *(undefined4 *)(param_4 + iVar4) = *(undefined4 *)(iVar3 + 0x10);
        uStack132 = (int)*(char *)(iVar9 + 0x2c) << 8 ^ 0x80000000;
        local_88 = 0x43300000;
        dVar11 = (double)FUN_80293e80((double)((FLOAT_803e0614 *
                                               (float)((double)CONCAT44(0x43300000,uStack132) -
                                                      DOUBLE_803e0620)) / FLOAT_803e0618));
        uStack124 = (uint)*(byte *)(iVar9 + 0x2e);
        local_80 = 0x43300000;
        *(float *)(iVar2 + iVar8 + 8) =
             FLOAT_803e0610 *
             (float)((double)(float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803e0628) *
                    dVar11);
        uStack116 = (int)*(char *)(iVar9 + 0x2d) << 8 ^ 0x80000000;
        local_78 = 0x43300000;
        dVar11 = (double)FUN_80293e80((double)((FLOAT_803e0614 *
                                               (float)((double)CONCAT44(0x43300000,uStack116) -
                                                      DOUBLE_803e0620)) / FLOAT_803e0618));
        uStack108 = (uint)*(byte *)(iVar9 + 0x2e);
        local_70 = 0x43300000;
        *(float *)(param_3 + iVar8 + 8) =
             FLOAT_803e0610 *
             (float)((double)(float)((double)CONCAT44(0x43300000,uStack108) - DOUBLE_803e0628) *
                    dVar11);
        uStack100 = (int)*(char *)(iVar9 + 0x2c) << 8 ^ 0x80000000;
        local_68 = 0x43300000;
        dVar11 = (double)FUN_80294204((double)((FLOAT_803e0614 *
                                               (float)((double)CONCAT44(0x43300000,uStack100) -
                                                      DOUBLE_803e0620)) / FLOAT_803e0618));
        uStack92 = (uint)*(byte *)(iVar9 + 0x2e);
        local_60 = 0x43300000;
        iVar9 = iVar10 + 3;
        *(float *)(param_4 + (iVar10 + 2) * 4) =
             FLOAT_803e0610 *
             (float)((double)(float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e0628) *
                    dVar11);
        uStack84 = (int)*(char *)(iVar3 + 0x2c) << 8 ^ 0x80000000;
        local_58 = 0x43300000;
        dVar11 = (double)FUN_80293e80((double)((FLOAT_803e0614 *
                                               (float)((double)CONCAT44(0x43300000,uStack84) -
                                                      DOUBLE_803e0620)) / FLOAT_803e0618));
        uStack76 = (uint)*(byte *)(iVar3 + 0x2e);
        local_50 = 0x43300000;
        *(float *)(iVar2 + iVar8 + 0xc) =
             FLOAT_803e0610 *
             (float)((double)(float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e0628) *
                    dVar11);
        uStack68 = (int)*(char *)(iVar3 + 0x2d) << 8 ^ 0x80000000;
        local_48 = 0x43300000;
        dVar11 = (double)FUN_80293e80((double)((FLOAT_803e0614 *
                                               (float)((double)CONCAT44(0x43300000,uStack68) -
                                                      DOUBLE_803e0620)) / FLOAT_803e0618));
        uStack60 = (uint)*(byte *)(iVar3 + 0x2e);
        local_40 = 0x43300000;
        *(float *)(param_3 + iVar8 + 0xc) =
             FLOAT_803e0610 *
             (float)((double)(float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e0628) *
                    dVar11);
        uStack52 = (int)*(char *)(iVar3 + 0x2c) << 8 ^ 0x80000000;
        local_38 = 0x43300000;
        dVar11 = (double)FUN_80294204((double)((FLOAT_803e0614 *
                                               (float)((double)CONCAT44(0x43300000,uStack52) -
                                                      DOUBLE_803e0620)) / FLOAT_803e0618));
        uStack44 = (uint)*(byte *)(iVar3 + 0x2e);
        local_30 = 0x43300000;
        iVar10 = iVar10 + 4;
        iVar8 = iVar8 + 0x10;
        *(float *)(param_4 + iVar9 * 4) =
             FLOAT_803e0610 *
             (float)((double)(float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e0628) *
                    dVar11);
      }
    }
  }
  FUN_80286114(iVar10);
  return;
}

