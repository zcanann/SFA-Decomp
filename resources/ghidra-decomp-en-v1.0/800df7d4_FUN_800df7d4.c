// Function: FUN_800df7d4
// Entry: 800df7d4
// Size: 2388 bytes

/* WARNING: Removing unreachable block (ram,0x800e0114) */

undefined4
FUN_800df7d4(double param_1,int param_2,int param_3,undefined4 param_4,undefined4 param_5)

{
  float fVar1;
  float fVar2;
  float fVar3;
  undefined4 uVar4;
  uint uVar5;
  char cVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  undefined4 uVar11;
  double dVar12;
  undefined8 in_f31;
  uint local_a8 [4];
  uint local_98 [4];
  uint local_88 [4];
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
  undefined4 local_28;
  uint uStack36;
  undefined4 local_20;
  uint uStack28;
  undefined auStack8 [8];
  
  uVar11 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  if (param_2 == 0) {
    uVar4 = 1;
  }
  else {
    uVar5 = FUN_800e0134(param_3,param_4,1,param_5,0xc);
    if (uVar5 == 0xffffffff) {
      uVar4 = 1;
    }
    else {
      if (*(int *)(param_2 + 0x80) != 0) {
        if ((int)uVar5 < 0) {
          iVar10 = 0;
        }
        else {
          iVar9 = DAT_803dd478 + -1;
          iVar7 = 0;
          while (iVar7 <= iVar9) {
            iVar8 = iVar9 + iVar7 >> 1;
            iVar10 = (&DAT_803a17e8)[iVar8];
            if (*(uint *)(iVar10 + 0x14) < uVar5) {
              iVar7 = iVar8 + 1;
            }
            else {
              if (*(uint *)(iVar10 + 0x14) <= uVar5) goto LAB_800df89c;
              iVar9 = iVar8 + -1;
            }
          }
          iVar10 = 0;
        }
LAB_800df89c:
        *(int *)(param_2 + 0xa0) = iVar10;
        iVar9 = *(int *)(param_2 + 0xa0);
        iVar7 = 0;
        uVar5 = *(uint *)(iVar9 + 0x1c);
        if (((-1 < (int)uVar5) && ((*(byte *)(iVar9 + 0x1b) & 1) == 0)) && (uVar5 != 0xffffffff)) {
          iVar7 = 1;
          local_88[0] = uVar5;
        }
        uVar5 = *(uint *)(iVar9 + 0x20);
        iVar8 = iVar7;
        if (((-1 < (int)uVar5) && ((*(byte *)(iVar9 + 0x1b) & 2) == 0)) && (uVar5 != 0xffffffff)) {
          iVar8 = iVar7 + 1;
          local_88[iVar7] = uVar5;
        }
        uVar5 = *(uint *)(iVar9 + 0x24);
        iVar7 = iVar8;
        if (((-1 < (int)uVar5) && ((*(byte *)(iVar9 + 0x1b) & 4) == 0)) && (uVar5 != 0xffffffff)) {
          iVar7 = iVar8 + 1;
          local_88[iVar8] = uVar5;
        }
        uVar5 = *(uint *)(iVar9 + 0x28);
        iVar8 = iVar7;
        if (((-1 < (int)uVar5) && ((*(byte *)(iVar9 + 0x1b) & 8) == 0)) && (uVar5 != 0xffffffff)) {
          iVar8 = iVar7 + 1;
          local_88[iVar7] = uVar5;
        }
        if (iVar8 == 0) {
          uVar5 = 0xffffffff;
        }
        else {
          iVar7 = FUN_800221a0(0,iVar8 + -1);
          uVar5 = local_88[iVar7];
        }
        if (uVar5 == 0xffffffff) {
          uVar4 = 1;
          goto LAB_800e0114;
        }
      }
      if ((int)uVar5 < 0) {
        iVar10 = 0;
      }
      else {
        iVar9 = DAT_803dd478 + -1;
        iVar7 = 0;
        while (iVar7 <= iVar9) {
          iVar8 = iVar9 + iVar7 >> 1;
          iVar10 = (&DAT_803a17e8)[iVar8];
          if (*(uint *)(iVar10 + 0x14) < uVar5) {
            iVar7 = iVar8 + 1;
          }
          else {
            if (*(uint *)(iVar10 + 0x14) <= uVar5) goto LAB_800dfa3c;
            iVar9 = iVar8 + -1;
          }
        }
        iVar10 = 0;
      }
LAB_800dfa3c:
      *(int *)(param_2 + 0xa0) = iVar10;
      if (iVar10 == 0) {
        *(undefined4 *)(param_2 + 0xa0) = 0;
        uVar4 = 1;
      }
      else {
        if (*(int *)(param_2 + 0x80) == 0) {
          iVar9 = *(int *)(param_2 + 0xa0);
          iVar7 = 0;
          uVar5 = *(uint *)(iVar9 + 0x1c);
          if (((-1 < (int)uVar5) && ((*(byte *)(iVar9 + 0x1b) & 1) == 0)) && (uVar5 != 0xffffffff))
          {
            iVar7 = 1;
            local_a8[0] = uVar5;
          }
          uVar5 = *(uint *)(iVar9 + 0x20);
          iVar8 = iVar7;
          if (((-1 < (int)uVar5) && ((*(byte *)(iVar9 + 0x1b) & 2) == 0)) && (uVar5 != 0xffffffff))
          {
            iVar8 = iVar7 + 1;
            local_a8[iVar7] = uVar5;
          }
          uVar5 = *(uint *)(iVar9 + 0x24);
          iVar7 = iVar8;
          if (((-1 < (int)uVar5) && ((*(byte *)(iVar9 + 0x1b) & 4) == 0)) && (uVar5 != 0xffffffff))
          {
            iVar7 = iVar8 + 1;
            local_a8[iVar8] = uVar5;
          }
          uVar5 = *(uint *)(iVar9 + 0x28);
          iVar8 = iVar7;
          if (((-1 < (int)uVar5) && ((*(byte *)(iVar9 + 0x1b) & 8) == 0)) && (uVar5 != 0xffffffff))
          {
            iVar8 = iVar7 + 1;
            local_a8[iVar7] = uVar5;
          }
          if (iVar8 == 0) {
            uVar5 = 0xffffffff;
          }
          else {
            iVar7 = FUN_800221a0(0,iVar8 + -1);
            uVar5 = local_a8[iVar7];
          }
        }
        else {
          iVar9 = *(int *)(param_2 + 0xa0);
          iVar7 = 0;
          uVar5 = *(uint *)(iVar9 + 0x1c);
          if (((-1 < (int)uVar5) && ((*(byte *)(iVar9 + 0x1b) & 1) != 0)) && (uVar5 != 0xffffffff))
          {
            iVar7 = 1;
            local_98[0] = uVar5;
          }
          uVar5 = *(uint *)(iVar9 + 0x20);
          iVar8 = iVar7;
          if (((-1 < (int)uVar5) && ((*(byte *)(iVar9 + 0x1b) & 2) != 0)) && (uVar5 != 0xffffffff))
          {
            iVar8 = iVar7 + 1;
            local_98[iVar7] = uVar5;
          }
          uVar5 = *(uint *)(iVar9 + 0x24);
          iVar7 = iVar8;
          if (((-1 < (int)uVar5) && ((*(byte *)(iVar9 + 0x1b) & 4) != 0)) && (uVar5 != 0xffffffff))
          {
            iVar7 = iVar8 + 1;
            local_98[iVar8] = uVar5;
          }
          uVar5 = *(uint *)(iVar9 + 0x28);
          iVar8 = iVar7;
          if (((-1 < (int)uVar5) && ((*(byte *)(iVar9 + 0x1b) & 8) != 0)) && (uVar5 != 0xffffffff))
          {
            iVar8 = iVar7 + 1;
            local_98[iVar7] = uVar5;
          }
          if (iVar8 == 0) {
            uVar5 = 0xffffffff;
          }
          else {
            iVar7 = FUN_800221a0(0,iVar8 + -1);
            uVar5 = local_98[iVar7];
          }
        }
        if (uVar5 == 0xffffffff) {
          uVar4 = 1;
        }
        else {
          if ((int)uVar5 < 0) {
            iVar10 = 0;
          }
          else {
            iVar9 = DAT_803dd478 + -1;
            iVar7 = 0;
            while (iVar7 <= iVar9) {
              iVar8 = iVar9 + iVar7 >> 1;
              iVar10 = (&DAT_803a17e8)[iVar8];
              if (*(uint *)(iVar10 + 0x14) < uVar5) {
                iVar7 = iVar8 + 1;
              }
              else {
                if (*(uint *)(iVar10 + 0x14) <= uVar5) goto LAB_800dfd30;
                iVar9 = iVar8 + -1;
              }
            }
            iVar10 = 0;
          }
LAB_800dfd30:
          *(int *)(param_2 + 0xa4) = iVar10;
          if (iVar10 == 0) {
            *(undefined4 *)(param_2 + 0xa4) = 0;
            uVar4 = 1;
          }
          else {
            if (param_1 != (double)FLOAT_803e0638) {
              if (*(int *)(param_2 + 0x80) == 0) {
                iVar7 = *(int *)(param_2 + 0xa0);
                fVar1 = *(float *)(iVar7 + 8) - *(float *)(param_3 + 0xc);
                fVar2 = *(float *)(iVar7 + 0xc) - *(float *)(param_3 + 0x10);
                fVar3 = *(float *)(iVar7 + 0x10) - *(float *)(param_3 + 0x14);
              }
              else {
                iVar7 = *(int *)(param_2 + 0xa4);
                fVar1 = *(float *)(iVar7 + 8) - *(float *)(param_3 + 0xc);
                fVar2 = *(float *)(iVar7 + 0xc) - *(float *)(param_3 + 0x10);
                fVar3 = *(float *)(iVar7 + 0x10) - *(float *)(param_3 + 0x14);
              }
              dVar12 = (double)FUN_802931a0((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2))
              ;
              if (param_1 < dVar12) {
                uVar4 = 1;
                goto LAB_800e0114;
              }
            }
            *(undefined4 *)(param_2 + 0xb8) = *(undefined4 *)(*(int *)(param_2 + 0xa0) + 8);
            *(undefined4 *)(param_2 + 0xbc) = *(undefined4 *)(*(int *)(param_2 + 0xa4) + 8);
            uStack116 = (int)*(char *)(*(int *)(param_2 + 0xa0) + 0x2c) << 8 ^ 0x80000000;
            local_78 = 0x43300000;
            dVar12 = (double)FUN_80293e80((double)((FLOAT_803e0614 *
                                                   (float)((double)CONCAT44(0x43300000,uStack116) -
                                                          DOUBLE_803e0620)) / FLOAT_803e0618));
            uStack108 = (uint)*(byte *)(*(int *)(param_2 + 0xa0) + 0x2e);
            local_70 = 0x43300000;
            *(float *)(param_2 + 0xc0) =
                 FLOAT_803e0610 *
                 (float)((double)(float)((double)CONCAT44(0x43300000,uStack108) - DOUBLE_803e0628) *
                        dVar12);
            uStack100 = (int)*(char *)(*(int *)(param_2 + 0xa4) + 0x2c) << 8 ^ 0x80000000;
            local_68 = 0x43300000;
            dVar12 = (double)FUN_80293e80((double)((FLOAT_803e0614 *
                                                   (float)((double)CONCAT44(0x43300000,uStack100) -
                                                          DOUBLE_803e0620)) / FLOAT_803e0618));
            uStack92 = (uint)*(byte *)(*(int *)(param_2 + 0xa4) + 0x2e);
            local_60 = 0x43300000;
            *(float *)(param_2 + 0xc4) =
                 FLOAT_803e0610 *
                 (float)((double)(float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e0628) *
                        dVar12);
            *(undefined4 *)(param_2 + 0xd8) = *(undefined4 *)(*(int *)(param_2 + 0xa0) + 0xc);
            *(undefined4 *)(param_2 + 0xdc) = *(undefined4 *)(*(int *)(param_2 + 0xa4) + 0xc);
            uStack84 = (int)*(char *)(*(int *)(param_2 + 0xa0) + 0x2d) << 8 ^ 0x80000000;
            local_58 = 0x43300000;
            dVar12 = (double)FUN_80293e80((double)((FLOAT_803e0614 *
                                                   (float)((double)CONCAT44(0x43300000,uStack84) -
                                                          DOUBLE_803e0620)) / FLOAT_803e0618));
            uStack76 = (uint)*(byte *)(*(int *)(param_2 + 0xa0) + 0x2e);
            local_50 = 0x43300000;
            *(float *)(param_2 + 0xe0) =
                 FLOAT_803e0610 *
                 (float)((double)(float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e0628) *
                        dVar12);
            uStack68 = (int)*(char *)(*(int *)(param_2 + 0xa4) + 0x2d) << 8 ^ 0x80000000;
            local_48 = 0x43300000;
            dVar12 = (double)FUN_80293e80((double)((FLOAT_803e0614 *
                                                   (float)((double)CONCAT44(0x43300000,uStack68) -
                                                          DOUBLE_803e0620)) / FLOAT_803e0618));
            uStack60 = (uint)*(byte *)(*(int *)(param_2 + 0xa4) + 0x2e);
            local_40 = 0x43300000;
            *(float *)(param_2 + 0xe4) =
                 FLOAT_803e0610 *
                 (float)((double)(float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e0628) *
                        dVar12);
            *(undefined4 *)(param_2 + 0xf8) = *(undefined4 *)(*(int *)(param_2 + 0xa0) + 0x10);
            *(undefined4 *)(param_2 + 0xfc) = *(undefined4 *)(*(int *)(param_2 + 0xa4) + 0x10);
            uStack52 = (int)*(char *)(*(int *)(param_2 + 0xa0) + 0x2c) << 8 ^ 0x80000000;
            local_38 = 0x43300000;
            dVar12 = (double)FUN_80294204((double)((FLOAT_803e0614 *
                                                   (float)((double)CONCAT44(0x43300000,uStack52) -
                                                          DOUBLE_803e0620)) / FLOAT_803e0618));
            uStack44 = (uint)*(byte *)(*(int *)(param_2 + 0xa0) + 0x2e);
            local_30 = 0x43300000;
            *(float *)(param_2 + 0x100) =
                 FLOAT_803e0610 *
                 (float)((double)(float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e0628) *
                        dVar12);
            uStack36 = (int)*(char *)(*(int *)(param_2 + 0xa4) + 0x2c) << 8 ^ 0x80000000;
            local_28 = 0x43300000;
            dVar12 = (double)FUN_80294204((double)((FLOAT_803e0614 *
                                                   (float)((double)CONCAT44(0x43300000,uStack36) -
                                                          DOUBLE_803e0620)) / FLOAT_803e0618));
            uStack28 = (uint)*(byte *)(*(int *)(param_2 + 0xa4) + 0x2e);
            local_20 = 0x43300000;
            *(float *)(param_2 + 0x104) =
                 FLOAT_803e0610 *
                 (float)((double)(float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e0628) *
                        dVar12);
            cVar6 = FUN_800dee58(param_2);
            if (cVar6 == '\0') {
              *(code **)(param_2 + 0x94) = FUN_80010dc0;
              *(undefined **)(param_2 + 0x98) = &LAB_80010d54;
              *(int *)(param_2 + 0x84) = param_2 + 0xa8;
              *(int *)(param_2 + 0x88) = param_2 + 200;
              *(int *)(param_2 + 0x8c) = param_2 + 0xe8;
              *(undefined4 *)(param_2 + 0x90) = 8;
              FUN_80010a6c(param_2);
              uVar4 = 0;
            }
            else {
              uVar4 = 1;
            }
          }
        }
      }
    }
  }
LAB_800e0114:
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  return uVar4;
}

