// Function: FUN_800dee58
// Entry: 800dee58
// Size: 2424 bytes

undefined4 FUN_800dee58(int param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  double dVar6;
  uint local_88 [4];
  uint local_78 [4];
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
  undefined4 local_28;
  uint uStack36;
  undefined4 local_20;
  uint uStack28;
  undefined4 local_18;
  uint uStack20;
  undefined4 local_10;
  uint uStack12;
  
  if (((param_1 != 0) && (*(int *)(param_1 + 0xa0) != 0)) && (*(int *)(param_1 + 0xa4) != 0)) {
    *(int *)(param_1 + 0x9c) = *(int *)(param_1 + 0xa0);
    *(undefined4 *)(param_1 + 0xa0) = *(undefined4 *)(param_1 + 0xa4);
    FUN_80003494(param_1 + 0xa8,param_1 + 0xb8,0x10);
    FUN_80003494(param_1 + 200,param_1 + 0xd8,0x10);
    FUN_80003494(param_1 + 0xe8,param_1 + 0xf8,0x10);
    if (*(int *)(param_1 + 0x80) == 0) {
      iVar3 = *(int *)(param_1 + 0xa0);
      iVar1 = 0;
      uVar4 = *(uint *)(iVar3 + 0x1c);
      if (((-1 < (int)uVar4) && ((*(byte *)(iVar3 + 0x1b) & 1) == 0)) && (uVar4 != 0xffffffff)) {
        iVar1 = 1;
        local_88[0] = uVar4;
      }
      uVar4 = *(uint *)(iVar3 + 0x20);
      iVar2 = iVar1;
      if (((-1 < (int)uVar4) && ((*(byte *)(iVar3 + 0x1b) & 2) == 0)) && (uVar4 != 0xffffffff)) {
        iVar2 = iVar1 + 1;
        local_88[iVar1] = uVar4;
      }
      uVar4 = *(uint *)(iVar3 + 0x24);
      iVar1 = iVar2;
      if (((-1 < (int)uVar4) && ((*(byte *)(iVar3 + 0x1b) & 4) == 0)) && (uVar4 != 0xffffffff)) {
        iVar1 = iVar2 + 1;
        local_88[iVar2] = uVar4;
      }
      uVar4 = *(uint *)(iVar3 + 0x28);
      iVar2 = iVar1;
      if (((-1 < (int)uVar4) && ((*(byte *)(iVar3 + 0x1b) & 8) == 0)) && (uVar4 != 0xffffffff)) {
        iVar2 = iVar1 + 1;
        local_88[iVar1] = uVar4;
      }
      if (iVar2 == 0) {
        uVar4 = 0xffffffff;
      }
      else {
        iVar1 = FUN_800221a0(0,iVar2 + -1);
        uVar4 = local_88[iVar1];
      }
    }
    else {
      iVar3 = *(int *)(param_1 + 0xa0);
      iVar1 = 0;
      uVar4 = *(uint *)(iVar3 + 0x1c);
      if (((-1 < (int)uVar4) && ((*(byte *)(iVar3 + 0x1b) & 1) != 0)) && (uVar4 != 0xffffffff)) {
        iVar1 = 1;
        local_78[0] = uVar4;
      }
      uVar4 = *(uint *)(iVar3 + 0x20);
      iVar2 = iVar1;
      if (((-1 < (int)uVar4) && ((*(byte *)(iVar3 + 0x1b) & 2) != 0)) && (uVar4 != 0xffffffff)) {
        iVar2 = iVar1 + 1;
        local_78[iVar1] = uVar4;
      }
      uVar4 = *(uint *)(iVar3 + 0x24);
      iVar1 = iVar2;
      if (((-1 < (int)uVar4) && ((*(byte *)(iVar3 + 0x1b) & 4) != 0)) && (uVar4 != 0xffffffff)) {
        iVar1 = iVar2 + 1;
        local_78[iVar2] = uVar4;
      }
      uVar4 = *(uint *)(iVar3 + 0x28);
      iVar2 = iVar1;
      if (((-1 < (int)uVar4) && ((*(byte *)(iVar3 + 0x1b) & 8) != 0)) && (uVar4 != 0xffffffff)) {
        iVar2 = iVar1 + 1;
        local_78[iVar1] = uVar4;
      }
      if (iVar2 == 0) {
        uVar4 = 0xffffffff;
      }
      else {
        iVar1 = FUN_800221a0(0,iVar2 + -1);
        uVar4 = local_78[iVar1];
      }
    }
    if (uVar4 == 0xffffffff) {
      *(undefined4 *)(param_1 + 0xa4) = 0;
    }
    else {
      if ((int)uVar4 < 0) {
        iVar5 = 0;
      }
      else {
        iVar3 = DAT_803dd478 + -1;
        iVar1 = 0;
        while (iVar1 <= iVar3) {
          iVar2 = iVar3 + iVar1 >> 1;
          iVar5 = (&DAT_803a17e8)[iVar2];
          if (*(uint *)(iVar5 + 0x14) < uVar4) {
            iVar1 = iVar2 + 1;
          }
          else {
            if (*(uint *)(iVar5 + 0x14) <= uVar4) goto LAB_800df1a8;
            iVar3 = iVar2 + -1;
          }
        }
        iVar5 = 0;
      }
LAB_800df1a8:
      *(int *)(param_1 + 0xa4) = iVar5;
      if (*(int *)(param_1 + 0xa4) != 0) {
        if (*(int *)(param_1 + 0x80) == 0) {
          *(undefined4 *)(param_1 + 0xb8) = *(undefined4 *)(*(int *)(param_1 + 0xa0) + 8);
          *(undefined4 *)(param_1 + 0xbc) = *(undefined4 *)(*(int *)(param_1 + 0xa4) + 8);
          uStack12 = (int)*(char *)(*(int *)(param_1 + 0xa0) + 0x2c) << 8 ^ 0x80000000;
          local_10 = 0x43300000;
          dVar6 = (double)FUN_80293e80((double)((FLOAT_803e0614 *
                                                (float)((double)CONCAT44(0x43300000,uStack12) -
                                                       DOUBLE_803e0620)) / FLOAT_803e0618));
          uStack20 = (uint)*(byte *)(*(int *)(param_1 + 0xa0) + 0x2e);
          local_18 = 0x43300000;
          *(float *)(param_1 + 0xc0) =
               FLOAT_803e0610 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e0628) *
                      dVar6);
          uStack28 = (int)*(char *)(*(int *)(param_1 + 0xa4) + 0x2c) << 8 ^ 0x80000000;
          local_20 = 0x43300000;
          dVar6 = (double)FUN_80293e80((double)((FLOAT_803e0614 *
                                                (float)((double)CONCAT44(0x43300000,uStack28) -
                                                       DOUBLE_803e0620)) / FLOAT_803e0618));
          uStack36 = (uint)*(byte *)(*(int *)(param_1 + 0xa4) + 0x2e);
          local_28 = 0x43300000;
          *(float *)(param_1 + 0xc4) =
               FLOAT_803e0610 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e0628) *
                      dVar6);
          *(undefined4 *)(param_1 + 0xd8) = *(undefined4 *)(*(int *)(param_1 + 0xa0) + 0xc);
          *(undefined4 *)(param_1 + 0xdc) = *(undefined4 *)(*(int *)(param_1 + 0xa4) + 0xc);
          uStack44 = (int)*(char *)(*(int *)(param_1 + 0xa0) + 0x2d) << 8 ^ 0x80000000;
          local_30 = 0x43300000;
          dVar6 = (double)FUN_80293e80((double)((FLOAT_803e0614 *
                                                (float)((double)CONCAT44(0x43300000,uStack44) -
                                                       DOUBLE_803e0620)) / FLOAT_803e0618));
          uStack52 = (uint)*(byte *)(*(int *)(param_1 + 0xa0) + 0x2e);
          local_38 = 0x43300000;
          *(float *)(param_1 + 0xe0) =
               FLOAT_803e0610 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e0628) *
                      dVar6);
          uStack60 = (int)*(char *)(*(int *)(param_1 + 0xa4) + 0x2d) << 8 ^ 0x80000000;
          local_40 = 0x43300000;
          dVar6 = (double)FUN_80293e80((double)((FLOAT_803e0614 *
                                                (float)((double)CONCAT44(0x43300000,uStack60) -
                                                       DOUBLE_803e0620)) / FLOAT_803e0618));
          uStack68 = (uint)*(byte *)(*(int *)(param_1 + 0xa4) + 0x2e);
          local_48 = 0x43300000;
          *(float *)(param_1 + 0xe4) =
               FLOAT_803e0610 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e0628) *
                      dVar6);
          *(undefined4 *)(param_1 + 0xf8) = *(undefined4 *)(*(int *)(param_1 + 0xa0) + 0x10);
          *(undefined4 *)(param_1 + 0xfc) = *(undefined4 *)(*(int *)(param_1 + 0xa4) + 0x10);
          uStack76 = (int)*(char *)(*(int *)(param_1 + 0xa0) + 0x2c) << 8 ^ 0x80000000;
          local_50 = 0x43300000;
          dVar6 = (double)FUN_80294204((double)((FLOAT_803e0614 *
                                                (float)((double)CONCAT44(0x43300000,uStack76) -
                                                       DOUBLE_803e0620)) / FLOAT_803e0618));
          uStack84 = (uint)*(byte *)(*(int *)(param_1 + 0xa0) + 0x2e);
          local_58 = 0x43300000;
          *(float *)(param_1 + 0x100) =
               FLOAT_803e0610 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803e0628) *
                      dVar6);
          uStack92 = (int)*(char *)(*(int *)(param_1 + 0xa4) + 0x2c) << 8 ^ 0x80000000;
          local_60 = 0x43300000;
          dVar6 = (double)FUN_80294204((double)((FLOAT_803e0614 *
                                                (float)((double)CONCAT44(0x43300000,uStack92) -
                                                       DOUBLE_803e0620)) / FLOAT_803e0618));
          uStack100 = (uint)*(byte *)(*(int *)(param_1 + 0xa4) + 0x2e);
          local_68 = 0x43300000;
          *(float *)(param_1 + 0x104) =
               FLOAT_803e0610 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack100) - DOUBLE_803e0628) *
                      dVar6);
        }
        else {
          *(undefined4 *)(param_1 + 0xb8) = *(undefined4 *)(*(int *)(param_1 + 0xa0) + 8);
          *(undefined4 *)(param_1 + 0xbc) = *(undefined4 *)(*(int *)(param_1 + 0x9c) + 8);
          uStack100 = (int)*(char *)(*(int *)(param_1 + 0xa0) + 0x2c) << 8 ^ 0x80000000;
          local_68 = 0x43300000;
          dVar6 = (double)FUN_80293e80((double)((FLOAT_803e0614 *
                                                (float)((double)CONCAT44(0x43300000,uStack100) -
                                                       DOUBLE_803e0620)) / FLOAT_803e0618));
          uStack92 = (uint)*(byte *)(*(int *)(param_1 + 0xa0) + 0x2e);
          local_60 = 0x43300000;
          *(float *)(param_1 + 0xc0) =
               FLOAT_803e0610 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e0628) *
                      dVar6);
          uStack84 = (int)*(char *)(*(int *)(param_1 + 0x9c) + 0x2c) << 8 ^ 0x80000000;
          local_58 = 0x43300000;
          dVar6 = (double)FUN_80293e80((double)((FLOAT_803e0614 *
                                                (float)((double)CONCAT44(0x43300000,uStack84) -
                                                       DOUBLE_803e0620)) / FLOAT_803e0618));
          uStack76 = (uint)*(byte *)(*(int *)(param_1 + 0x9c) + 0x2e);
          local_50 = 0x43300000;
          *(float *)(param_1 + 0xc4) =
               FLOAT_803e0610 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e0628) *
                      dVar6);
          *(undefined4 *)(param_1 + 0xd8) = *(undefined4 *)(*(int *)(param_1 + 0xa0) + 0xc);
          *(undefined4 *)(param_1 + 0xdc) = *(undefined4 *)(*(int *)(param_1 + 0x9c) + 0xc);
          uStack68 = (int)*(char *)(*(int *)(param_1 + 0xa0) + 0x2d) << 8 ^ 0x80000000;
          local_48 = 0x43300000;
          dVar6 = (double)FUN_80293e80((double)((FLOAT_803e0614 *
                                                (float)((double)CONCAT44(0x43300000,uStack68) -
                                                       DOUBLE_803e0620)) / FLOAT_803e0618));
          uStack60 = (uint)*(byte *)(*(int *)(param_1 + 0xa0) + 0x2e);
          local_40 = 0x43300000;
          *(float *)(param_1 + 0xe0) =
               FLOAT_803e0610 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e0628) *
                      dVar6);
          uStack52 = (int)*(char *)(*(int *)(param_1 + 0x9c) + 0x2d) << 8 ^ 0x80000000;
          local_38 = 0x43300000;
          dVar6 = (double)FUN_80293e80((double)((FLOAT_803e0614 *
                                                (float)((double)CONCAT44(0x43300000,uStack52) -
                                                       DOUBLE_803e0620)) / FLOAT_803e0618));
          uStack44 = (uint)*(byte *)(*(int *)(param_1 + 0x9c) + 0x2e);
          local_30 = 0x43300000;
          *(float *)(param_1 + 0xe4) =
               FLOAT_803e0610 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e0628) *
                      dVar6);
          *(undefined4 *)(param_1 + 0xf8) = *(undefined4 *)(*(int *)(param_1 + 0xa0) + 0x10);
          *(undefined4 *)(param_1 + 0xfc) = *(undefined4 *)(*(int *)(param_1 + 0x9c) + 0x10);
          uStack36 = (int)*(char *)(*(int *)(param_1 + 0xa0) + 0x2c) << 8 ^ 0x80000000;
          local_28 = 0x43300000;
          dVar6 = (double)FUN_80294204((double)((FLOAT_803e0614 *
                                                (float)((double)CONCAT44(0x43300000,uStack36) -
                                                       DOUBLE_803e0620)) / FLOAT_803e0618));
          uStack28 = (uint)*(byte *)(*(int *)(param_1 + 0xa0) + 0x2e);
          local_20 = 0x43300000;
          *(float *)(param_1 + 0x100) =
               FLOAT_803e0610 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e0628) *
                      dVar6);
          uStack20 = (int)*(char *)(*(int *)(param_1 + 0x9c) + 0x2c) << 8 ^ 0x80000000;
          local_18 = 0x43300000;
          dVar6 = (double)FUN_80294204((double)((FLOAT_803e0614 *
                                                (float)((double)CONCAT44(0x43300000,uStack20) -
                                                       DOUBLE_803e0620)) / FLOAT_803e0618));
          uStack12 = (uint)*(byte *)(*(int *)(param_1 + 0x9c) + 0x2e);
          local_10 = 0x43300000;
          *(float *)(param_1 + 0x104) =
               FLOAT_803e0610 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack12) - DOUBLE_803e0628) *
                      dVar6);
        }
        if (*(int *)(param_1 + 0x90) != 0) {
          FUN_80010904(param_1);
        }
        if (*(int *)(param_1 + 0x80) == 0) {
          FUN_80010320((double)FLOAT_803e0634,param_1);
        }
        else {
          FUN_80010320((double)FLOAT_803e0630,param_1);
        }
        return 0;
      }
    }
  }
  return 1;
}

