// Function: FUN_800e3a00
// Entry: 800e3a00
// Size: 2988 bytes

void FUN_800e3a00(undefined4 param_1,undefined4 param_2,int param_3,int param_4,int param_5)

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
  uint uStack_84;
  undefined4 local_80;
  uint uStack_7c;
  undefined4 local_78;
  uint uStack_74;
  undefined4 local_70;
  uint uStack_6c;
  undefined4 local_68;
  uint uStack_64;
  undefined4 local_60;
  uint uStack_5c;
  undefined4 local_58;
  uint uStack_54;
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  
  uVar12 = FUN_8028682c();
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
        uVar5 = FUN_80022264(0,iVar4 - 1);
        uVar5 = local_a8[uVar5];
      }
      if ((int)uVar5 < 0) {
        iVar3 = 0;
      }
      else {
        iVar7 = DAT_803de0f0 + -1;
        iVar4 = 0;
        while (iVar4 <= iVar7) {
          iVar6 = iVar7 + iVar4 >> 1;
          iVar3 = (&DAT_803a2448)[iVar6];
          if (*(uint *)(iVar3 + 0x14) < uVar5) {
            iVar4 = iVar6 + 1;
          }
          else {
            if (*(uint *)(iVar3 + 0x14) <= uVar5) goto LAB_800e41e4;
            iVar7 = iVar6 + -1;
          }
        }
        iVar3 = 0;
      }
LAB_800e41e4:
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
        uStack_2c = (int)*(char *)(iVar8 + 0x2c) << 8 ^ 0x80000000;
        local_30 = 0x43300000;
        dVar11 = (double)FUN_802945e0();
        uStack_34 = (uint)*(byte *)(iVar8 + 0x2e);
        local_38 = 0x43300000;
        *(float *)(iVar2 + iVar9 + 8) =
             FLOAT_803e1290 *
             (float)((double)(float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e12a8) *
                    dVar11);
        uStack_3c = (int)*(char *)(iVar8 + 0x2d) << 8 ^ 0x80000000;
        local_40 = 0x43300000;
        dVar11 = (double)FUN_802945e0();
        uStack_44 = (uint)*(byte *)(iVar8 + 0x2e);
        local_48 = 0x43300000;
        *(float *)(param_3 + iVar9 + 8) =
             FLOAT_803e1290 *
             (float)((double)(float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e12a8) *
                    dVar11);
        uStack_4c = (int)*(char *)(iVar8 + 0x2c) << 8 ^ 0x80000000;
        local_50 = 0x43300000;
        dVar11 = (double)FUN_80294964();
        uStack_54 = (uint)*(byte *)(iVar8 + 0x2e);
        local_58 = 0x43300000;
        iVar8 = iVar10 + 3;
        *(float *)(param_4 + (iVar10 + 2) * 4) =
             FLOAT_803e1290 *
             (float)((double)(float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e12a8) *
                    dVar11);
        uStack_5c = (int)*(char *)(iVar3 + 0x2c) << 8 ^ 0x80000000;
        local_60 = 0x43300000;
        dVar11 = (double)FUN_802945e0();
        uStack_64 = (uint)*(byte *)(iVar3 + 0x2e);
        local_68 = 0x43300000;
        *(float *)(iVar2 + iVar9 + 0xc) =
             FLOAT_803e1290 *
             (float)((double)(float)((double)CONCAT44(0x43300000,uStack_64) - DOUBLE_803e12a8) *
                    dVar11);
        uStack_6c = (int)*(char *)(iVar3 + 0x2d) << 8 ^ 0x80000000;
        local_70 = 0x43300000;
        dVar11 = (double)FUN_802945e0();
        uStack_74 = (uint)*(byte *)(iVar3 + 0x2e);
        local_78 = 0x43300000;
        *(float *)(param_3 + iVar9 + 0xc) =
             FLOAT_803e1290 *
             (float)((double)(float)((double)CONCAT44(0x43300000,uStack_74) - DOUBLE_803e12a8) *
                    dVar11);
        uStack_7c = (int)*(char *)(iVar3 + 0x2c) << 8 ^ 0x80000000;
        local_80 = 0x43300000;
        dVar11 = (double)FUN_80294964();
        uStack_84 = (uint)*(byte *)(iVar3 + 0x2e);
        local_88 = 0x43300000;
        iVar10 = iVar10 + 4;
        iVar9 = iVar9 + 0x10;
        *(float *)(param_4 + iVar8 * 4) =
             FLOAT_803e1290 *
             (float)((double)(float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e12a8) *
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
        uVar5 = FUN_80022264(0,iVar4 - 1);
        uVar5 = local_98[uVar5];
      }
      if ((int)uVar5 < 0) {
        iVar3 = 0;
      }
      else {
        iVar7 = DAT_803de0f0 + -1;
        iVar4 = 0;
        while (iVar4 <= iVar7) {
          iVar6 = iVar7 + iVar4 >> 1;
          iVar3 = (&DAT_803a2448)[iVar6];
          if (*(uint *)(iVar3 + 0x14) < uVar5) {
            iVar4 = iVar6 + 1;
          }
          else {
            if (*(uint *)(iVar3 + 0x14) <= uVar5) goto LAB_800e3ca0;
            iVar7 = iVar6 + -1;
          }
        }
        iVar3 = 0;
      }
LAB_800e3ca0:
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
        uStack_84 = (int)*(char *)(iVar9 + 0x2c) << 8 ^ 0x80000000;
        local_88 = 0x43300000;
        dVar11 = (double)FUN_802945e0();
        uStack_7c = (uint)*(byte *)(iVar9 + 0x2e);
        local_80 = 0x43300000;
        *(float *)(iVar2 + iVar8 + 8) =
             FLOAT_803e1290 *
             (float)((double)(float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e12a8) *
                    dVar11);
        uStack_74 = (int)*(char *)(iVar9 + 0x2d) << 8 ^ 0x80000000;
        local_78 = 0x43300000;
        dVar11 = (double)FUN_802945e0();
        uStack_6c = (uint)*(byte *)(iVar9 + 0x2e);
        local_70 = 0x43300000;
        *(float *)(param_3 + iVar8 + 8) =
             FLOAT_803e1290 *
             (float)((double)(float)((double)CONCAT44(0x43300000,uStack_6c) - DOUBLE_803e12a8) *
                    dVar11);
        uStack_64 = (int)*(char *)(iVar9 + 0x2c) << 8 ^ 0x80000000;
        local_68 = 0x43300000;
        dVar11 = (double)FUN_80294964();
        uStack_5c = (uint)*(byte *)(iVar9 + 0x2e);
        local_60 = 0x43300000;
        iVar9 = iVar10 + 3;
        *(float *)(param_4 + (iVar10 + 2) * 4) =
             FLOAT_803e1290 *
             (float)((double)(float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e12a8) *
                    dVar11);
        uStack_54 = (int)*(char *)(iVar3 + 0x2c) << 8 ^ 0x80000000;
        local_58 = 0x43300000;
        dVar11 = (double)FUN_802945e0();
        uStack_4c = (uint)*(byte *)(iVar3 + 0x2e);
        local_50 = 0x43300000;
        *(float *)(iVar2 + iVar8 + 0xc) =
             FLOAT_803e1290 *
             (float)((double)(float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e12a8) *
                    dVar11);
        uStack_44 = (int)*(char *)(iVar3 + 0x2d) << 8 ^ 0x80000000;
        local_48 = 0x43300000;
        dVar11 = (double)FUN_802945e0();
        uStack_3c = (uint)*(byte *)(iVar3 + 0x2e);
        local_40 = 0x43300000;
        *(float *)(param_3 + iVar8 + 0xc) =
             FLOAT_803e1290 *
             (float)((double)(float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e12a8) *
                    dVar11);
        uStack_34 = (int)*(char *)(iVar3 + 0x2c) << 8 ^ 0x80000000;
        local_38 = 0x43300000;
        dVar11 = (double)FUN_80294964();
        uStack_2c = (uint)*(byte *)(iVar3 + 0x2e);
        local_30 = 0x43300000;
        iVar10 = iVar10 + 4;
        iVar8 = iVar8 + 0x10;
        *(float *)(param_4 + iVar9 * 4) =
             FLOAT_803e1290 *
             (float)((double)(float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e12a8) *
                    dVar11);
      }
    }
  }
  FUN_80286878();
  return;
}

