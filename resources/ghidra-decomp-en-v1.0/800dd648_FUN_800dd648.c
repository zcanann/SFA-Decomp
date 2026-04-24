// Function: FUN_800dd648
// Entry: 800dd648
// Size: 2196 bytes

undefined4 FUN_800dd648(int param_1,undefined4 param_2,uint param_3)

{
  undefined4 uVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  double dVar8;
  uint local_98 [4];
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
  
  if (param_1 == 0) {
    uVar1 = 1;
  }
  else if (param_3 == 0xffffffff) {
    uVar1 = 1;
  }
  else {
    if (*(int *)(param_1 + 0x80) != 0) {
      if ((int)param_3 < 0) {
        iVar7 = 0;
      }
      else {
        iVar5 = DAT_803dd478 + -1;
        iVar3 = 0;
        while (iVar3 <= iVar5) {
          iVar4 = iVar5 + iVar3 >> 1;
          iVar7 = (&DAT_803a17e8)[iVar4];
          if (*(uint *)(iVar7 + 0x14) < param_3) {
            iVar3 = iVar4 + 1;
          }
          else {
            if (*(uint *)(iVar7 + 0x14) <= param_3) goto LAB_800dd6e8;
            iVar5 = iVar4 + -1;
          }
        }
        iVar7 = 0;
      }
LAB_800dd6e8:
      *(int *)(param_1 + 0xa0) = iVar7;
      iVar5 = *(int *)(param_1 + 0xa0);
      iVar3 = 0;
      uVar6 = *(uint *)(iVar5 + 0x1c);
      if (((-1 < (int)uVar6) && ((*(byte *)(iVar5 + 0x1b) & 1) == 0)) && (uVar6 != 0xffffffff)) {
        iVar3 = 1;
        local_78[0] = uVar6;
      }
      uVar6 = *(uint *)(iVar5 + 0x20);
      iVar4 = iVar3;
      if (((-1 < (int)uVar6) && ((*(byte *)(iVar5 + 0x1b) & 2) == 0)) && (uVar6 != 0xffffffff)) {
        iVar4 = iVar3 + 1;
        local_78[iVar3] = uVar6;
      }
      uVar6 = *(uint *)(iVar5 + 0x24);
      iVar3 = iVar4;
      if (((-1 < (int)uVar6) && ((*(byte *)(iVar5 + 0x1b) & 4) == 0)) && (uVar6 != 0xffffffff)) {
        iVar3 = iVar4 + 1;
        local_78[iVar4] = uVar6;
      }
      uVar6 = *(uint *)(iVar5 + 0x28);
      iVar4 = iVar3;
      if (((-1 < (int)uVar6) && ((*(byte *)(iVar5 + 0x1b) & 8) == 0)) && (uVar6 != 0xffffffff)) {
        iVar4 = iVar3 + 1;
        local_78[iVar3] = uVar6;
      }
      if (iVar4 == 0) {
        param_3 = 0xffffffff;
      }
      else {
        iVar3 = FUN_800221a0(0,iVar4 + -1);
        param_3 = local_78[iVar3];
      }
      if (param_3 == 0xffffffff) {
        return 1;
      }
    }
    if ((int)param_3 < 0) {
      iVar7 = 0;
    }
    else {
      iVar5 = DAT_803dd478 + -1;
      iVar3 = 0;
      while (iVar3 <= iVar5) {
        iVar4 = iVar5 + iVar3 >> 1;
        iVar7 = (&DAT_803a17e8)[iVar4];
        if (*(uint *)(iVar7 + 0x14) < param_3) {
          iVar3 = iVar4 + 1;
        }
        else {
          if (*(uint *)(iVar7 + 0x14) <= param_3) goto LAB_800dd888;
          iVar5 = iVar4 + -1;
        }
      }
      iVar7 = 0;
    }
LAB_800dd888:
    *(int *)(param_1 + 0xa0) = iVar7;
    if (iVar7 == 0) {
      *(undefined4 *)(param_1 + 0xa0) = 0;
      uVar1 = 1;
    }
    else {
      if (*(int *)(param_1 + 0x80) == 0) {
        iVar5 = *(int *)(param_1 + 0xa0);
        iVar3 = 0;
        uVar6 = *(uint *)(iVar5 + 0x1c);
        if (((-1 < (int)uVar6) && ((*(byte *)(iVar5 + 0x1b) & 1) == 0)) && (uVar6 != 0xffffffff)) {
          iVar3 = 1;
          local_98[0] = uVar6;
        }
        uVar6 = *(uint *)(iVar5 + 0x20);
        iVar4 = iVar3;
        if (((-1 < (int)uVar6) && ((*(byte *)(iVar5 + 0x1b) & 2) == 0)) && (uVar6 != 0xffffffff)) {
          iVar4 = iVar3 + 1;
          local_98[iVar3] = uVar6;
        }
        uVar6 = *(uint *)(iVar5 + 0x24);
        iVar3 = iVar4;
        if (((-1 < (int)uVar6) && ((*(byte *)(iVar5 + 0x1b) & 4) == 0)) && (uVar6 != 0xffffffff)) {
          iVar3 = iVar4 + 1;
          local_98[iVar4] = uVar6;
        }
        uVar6 = *(uint *)(iVar5 + 0x28);
        iVar4 = iVar3;
        if (((-1 < (int)uVar6) && ((*(byte *)(iVar5 + 0x1b) & 8) == 0)) && (uVar6 != 0xffffffff)) {
          iVar4 = iVar3 + 1;
          local_98[iVar3] = uVar6;
        }
        if (iVar4 == 0) {
          uVar6 = 0xffffffff;
        }
        else {
          iVar3 = FUN_800221a0(0,iVar4 + -1);
          uVar6 = local_98[iVar3];
        }
      }
      else {
        iVar5 = *(int *)(param_1 + 0xa0);
        iVar3 = 0;
        uVar6 = *(uint *)(iVar5 + 0x1c);
        if (((-1 < (int)uVar6) && ((*(byte *)(iVar5 + 0x1b) & 1) != 0)) && (uVar6 != 0xffffffff)) {
          iVar3 = 1;
          local_88[0] = uVar6;
        }
        uVar6 = *(uint *)(iVar5 + 0x20);
        iVar4 = iVar3;
        if (((-1 < (int)uVar6) && ((*(byte *)(iVar5 + 0x1b) & 2) != 0)) && (uVar6 != 0xffffffff)) {
          iVar4 = iVar3 + 1;
          local_88[iVar3] = uVar6;
        }
        uVar6 = *(uint *)(iVar5 + 0x24);
        iVar3 = iVar4;
        if (((-1 < (int)uVar6) && ((*(byte *)(iVar5 + 0x1b) & 4) != 0)) && (uVar6 != 0xffffffff)) {
          iVar3 = iVar4 + 1;
          local_88[iVar4] = uVar6;
        }
        uVar6 = *(uint *)(iVar5 + 0x28);
        iVar4 = iVar3;
        if (((-1 < (int)uVar6) && ((*(byte *)(iVar5 + 0x1b) & 8) != 0)) && (uVar6 != 0xffffffff)) {
          iVar4 = iVar3 + 1;
          local_88[iVar3] = uVar6;
        }
        if (iVar4 == 0) {
          uVar6 = 0xffffffff;
        }
        else {
          iVar3 = FUN_800221a0(0,iVar4 + -1);
          uVar6 = local_88[iVar3];
        }
      }
      if (uVar6 == 0xffffffff) {
        uVar1 = 1;
      }
      else {
        if ((int)uVar6 < 0) {
          iVar7 = 0;
        }
        else {
          iVar5 = DAT_803dd478 + -1;
          iVar3 = 0;
          while (iVar3 <= iVar5) {
            iVar4 = iVar5 + iVar3 >> 1;
            iVar7 = (&DAT_803a17e8)[iVar4];
            if (*(uint *)(iVar7 + 0x14) < uVar6) {
              iVar3 = iVar4 + 1;
            }
            else {
              if (*(uint *)(iVar7 + 0x14) <= uVar6) goto LAB_800ddb7c;
              iVar5 = iVar4 + -1;
            }
          }
          iVar7 = 0;
        }
LAB_800ddb7c:
        *(int *)(param_1 + 0xa4) = iVar7;
        if (iVar7 == 0) {
          *(undefined4 *)(param_1 + 0xa4) = 0;
          uVar1 = 1;
        }
        else {
          *(undefined4 *)(param_1 + 0xb8) = *(undefined4 *)(*(int *)(param_1 + 0xa0) + 8);
          *(undefined4 *)(param_1 + 0xbc) = *(undefined4 *)(*(int *)(param_1 + 0xa4) + 8);
          uStack100 = (int)*(char *)(*(int *)(param_1 + 0xa0) + 0x2c) << 8 ^ 0x80000000;
          local_68 = 0x43300000;
          dVar8 = (double)FUN_80293e80((double)((FLOAT_803e0614 *
                                                (float)((double)CONCAT44(0x43300000,uStack100) -
                                                       DOUBLE_803e0620)) / FLOAT_803e0618));
          uStack92 = (uint)*(byte *)(*(int *)(param_1 + 0xa0) + 0x2e);
          local_60 = 0x43300000;
          *(float *)(param_1 + 0xc0) =
               FLOAT_803e0610 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e0628) *
                      dVar8);
          uStack84 = (int)*(char *)(*(int *)(param_1 + 0xa4) + 0x2c) << 8 ^ 0x80000000;
          local_58 = 0x43300000;
          dVar8 = (double)FUN_80293e80((double)((FLOAT_803e0614 *
                                                (float)((double)CONCAT44(0x43300000,uStack84) -
                                                       DOUBLE_803e0620)) / FLOAT_803e0618));
          uStack76 = (uint)*(byte *)(*(int *)(param_1 + 0xa4) + 0x2e);
          local_50 = 0x43300000;
          *(float *)(param_1 + 0xc4) =
               FLOAT_803e0610 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e0628) *
                      dVar8);
          *(undefined4 *)(param_1 + 0xd8) = *(undefined4 *)(*(int *)(param_1 + 0xa0) + 0xc);
          *(undefined4 *)(param_1 + 0xdc) = *(undefined4 *)(*(int *)(param_1 + 0xa4) + 0xc);
          uStack68 = (int)*(char *)(*(int *)(param_1 + 0xa0) + 0x2d) << 8 ^ 0x80000000;
          local_48 = 0x43300000;
          dVar8 = (double)FUN_80293e80((double)((FLOAT_803e0614 *
                                                (float)((double)CONCAT44(0x43300000,uStack68) -
                                                       DOUBLE_803e0620)) / FLOAT_803e0618));
          uStack60 = (uint)*(byte *)(*(int *)(param_1 + 0xa0) + 0x2e);
          local_40 = 0x43300000;
          *(float *)(param_1 + 0xe0) =
               FLOAT_803e0610 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e0628) *
                      dVar8);
          uStack52 = (int)*(char *)(*(int *)(param_1 + 0xa4) + 0x2d) << 8 ^ 0x80000000;
          local_38 = 0x43300000;
          dVar8 = (double)FUN_80293e80((double)((FLOAT_803e0614 *
                                                (float)((double)CONCAT44(0x43300000,uStack52) -
                                                       DOUBLE_803e0620)) / FLOAT_803e0618));
          uStack44 = (uint)*(byte *)(*(int *)(param_1 + 0xa4) + 0x2e);
          local_30 = 0x43300000;
          *(float *)(param_1 + 0xe4) =
               FLOAT_803e0610 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e0628) *
                      dVar8);
          *(undefined4 *)(param_1 + 0xf8) = *(undefined4 *)(*(int *)(param_1 + 0xa0) + 0x10);
          *(undefined4 *)(param_1 + 0xfc) = *(undefined4 *)(*(int *)(param_1 + 0xa4) + 0x10);
          uStack36 = (int)*(char *)(*(int *)(param_1 + 0xa0) + 0x2c) << 8 ^ 0x80000000;
          local_28 = 0x43300000;
          dVar8 = (double)FUN_80294204((double)((FLOAT_803e0614 *
                                                (float)((double)CONCAT44(0x43300000,uStack36) -
                                                       DOUBLE_803e0620)) / FLOAT_803e0618));
          uStack28 = (uint)*(byte *)(*(int *)(param_1 + 0xa0) + 0x2e);
          local_20 = 0x43300000;
          *(float *)(param_1 + 0x100) =
               FLOAT_803e0610 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e0628) *
                      dVar8);
          uStack20 = (int)*(char *)(*(int *)(param_1 + 0xa4) + 0x2c) << 8 ^ 0x80000000;
          local_18 = 0x43300000;
          dVar8 = (double)FUN_80294204((double)((FLOAT_803e0614 *
                                                (float)((double)CONCAT44(0x43300000,uStack20) -
                                                       DOUBLE_803e0620)) / FLOAT_803e0618));
          uStack12 = (uint)*(byte *)(*(int *)(param_1 + 0xa4) + 0x2e);
          local_10 = 0x43300000;
          *(float *)(param_1 + 0x104) =
               FLOAT_803e0610 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack12) - DOUBLE_803e0628) *
                      dVar8);
          cVar2 = FUN_800dee58(param_1);
          if (cVar2 == '\0') {
            *(code **)(param_1 + 0x94) = FUN_80010dc0;
            *(undefined **)(param_1 + 0x98) = &LAB_80010d54;
            *(int *)(param_1 + 0x84) = param_1 + 0xa8;
            *(int *)(param_1 + 0x88) = param_1 + 200;
            *(int *)(param_1 + 0x8c) = param_1 + 0xe8;
            *(undefined4 *)(param_1 + 0x90) = 8;
            FUN_80010a6c(param_1);
            uVar1 = 0;
          }
          else {
            uVar1 = 1;
          }
        }
      }
    }
  }
  return uVar1;
}

