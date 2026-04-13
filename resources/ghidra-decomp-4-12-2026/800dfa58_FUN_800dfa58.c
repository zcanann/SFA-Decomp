// Function: FUN_800dfa58
// Entry: 800dfa58
// Size: 2388 bytes

/* WARNING: Removing unreachable block (ram,0x800e0398) */
/* WARNING: Removing unreachable block (ram,0x800dfa68) */

undefined4
FUN_800dfa58(double param_1,undefined8 param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,float *param_9,int param_10,
            undefined4 param_11,int param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  float fVar2;
  undefined4 uVar3;
  uint uVar4;
  float fVar5;
  uint uVar6;
  undefined4 extraout_r4;
  int iVar7;
  int iVar8;
  int iVar9;
  float fVar10;
  float fVar11;
  double dVar12;
  double dVar13;
  uint local_a8 [4];
  uint local_98 [4];
  uint local_88 [4];
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
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  
  if (param_9 == (float *)0x0) {
    uVar3 = 1;
  }
  else {
    uVar4 = FUN_800e03b8(param_10,param_11,1,param_12,'\f');
    if (uVar4 == 0xffffffff) {
      uVar3 = 1;
    }
    else {
      if (param_9[0x20] != 0.0) {
        if ((int)uVar4 < 0) {
          fVar11 = 0.0;
        }
        else {
          iVar8 = DAT_803de0f0 + -1;
          iVar7 = 0;
          while (iVar7 <= iVar8) {
            iVar9 = iVar8 + iVar7 >> 1;
            fVar11 = (float)(&DAT_803a2448)[iVar9];
            if (*(uint *)((int)fVar11 + 0x14) < uVar4) {
              iVar7 = iVar9 + 1;
            }
            else {
              if (*(uint *)((int)fVar11 + 0x14) <= uVar4) goto LAB_800dfb20;
              iVar8 = iVar9 + -1;
            }
          }
          fVar11 = 0.0;
        }
LAB_800dfb20:
        param_9[0x28] = fVar11;
        fVar11 = param_9[0x28];
        iVar7 = 0;
        uVar4 = *(uint *)((int)fVar11 + 0x1c);
        if (((-1 < (int)uVar4) && ((*(byte *)((int)fVar11 + 0x1b) & 1) == 0)) &&
           (uVar4 != 0xffffffff)) {
          iVar7 = 1;
          local_88[0] = uVar4;
        }
        uVar4 = *(uint *)((int)fVar11 + 0x20);
        iVar8 = iVar7;
        if (((-1 < (int)uVar4) && ((*(byte *)((int)fVar11 + 0x1b) & 2) == 0)) &&
           (uVar4 != 0xffffffff)) {
          iVar8 = iVar7 + 1;
          local_88[iVar7] = uVar4;
        }
        uVar4 = *(uint *)((int)fVar11 + 0x24);
        iVar7 = iVar8;
        if (((-1 < (int)uVar4) && ((*(byte *)((int)fVar11 + 0x1b) & 4) == 0)) &&
           (uVar4 != 0xffffffff)) {
          iVar7 = iVar8 + 1;
          local_88[iVar8] = uVar4;
        }
        uVar4 = *(uint *)((int)fVar11 + 0x28);
        iVar8 = iVar7;
        if (((-1 < (int)uVar4) && ((*(byte *)((int)fVar11 + 0x1b) & 8) == 0)) &&
           (uVar4 != 0xffffffff)) {
          iVar8 = iVar7 + 1;
          local_88[iVar7] = uVar4;
        }
        if (iVar8 == 0) {
          uVar4 = 0xffffffff;
        }
        else {
          uVar4 = FUN_80022264(0,iVar8 - 1);
          uVar4 = local_88[uVar4];
        }
        if (uVar4 == 0xffffffff) {
          return 1;
        }
      }
      if ((int)uVar4 < 0) {
        fVar11 = 0.0;
      }
      else {
        iVar8 = DAT_803de0f0 + -1;
        iVar7 = 0;
        while (iVar7 <= iVar8) {
          iVar9 = iVar8 + iVar7 >> 1;
          fVar11 = (float)(&DAT_803a2448)[iVar9];
          if (*(uint *)((int)fVar11 + 0x14) < uVar4) {
            iVar7 = iVar9 + 1;
          }
          else {
            if (*(uint *)((int)fVar11 + 0x14) <= uVar4) goto LAB_800dfcc0;
            iVar8 = iVar9 + -1;
          }
        }
        fVar11 = 0.0;
      }
LAB_800dfcc0:
      param_9[0x28] = fVar11;
      if (fVar11 == 0.0) {
        param_9[0x28] = 0.0;
        uVar3 = 1;
      }
      else {
        if (param_9[0x20] == 0.0) {
          fVar11 = param_9[0x28];
          iVar7 = 0;
          uVar4 = *(uint *)((int)fVar11 + 0x1c);
          if (((-1 < (int)uVar4) && ((*(byte *)((int)fVar11 + 0x1b) & 1) == 0)) &&
             (uVar4 != 0xffffffff)) {
            iVar7 = 1;
            local_a8[0] = uVar4;
          }
          uVar4 = *(uint *)((int)fVar11 + 0x20);
          iVar8 = iVar7;
          if (((-1 < (int)uVar4) && ((*(byte *)((int)fVar11 + 0x1b) & 2) == 0)) &&
             (uVar4 != 0xffffffff)) {
            iVar8 = iVar7 + 1;
            local_a8[iVar7] = uVar4;
          }
          uVar4 = *(uint *)((int)fVar11 + 0x24);
          iVar7 = iVar8;
          if (((-1 < (int)uVar4) && ((*(byte *)((int)fVar11 + 0x1b) & 4) == 0)) &&
             (uVar4 != 0xffffffff)) {
            iVar7 = iVar8 + 1;
            local_a8[iVar8] = uVar4;
          }
          uVar4 = *(uint *)((int)fVar11 + 0x28);
          iVar8 = iVar7;
          if (((-1 < (int)uVar4) && ((*(byte *)((int)fVar11 + 0x1b) & 8) == 0)) &&
             (uVar4 != 0xffffffff)) {
            iVar8 = iVar7 + 1;
            local_a8[iVar7] = uVar4;
          }
          if (iVar8 == 0) {
            uVar4 = 0xffffffff;
          }
          else {
            uVar4 = FUN_80022264(0,iVar8 - 1);
            uVar4 = local_a8[uVar4];
          }
        }
        else {
          fVar11 = param_9[0x28];
          iVar7 = 0;
          uVar4 = *(uint *)((int)fVar11 + 0x1c);
          if (((-1 < (int)uVar4) && ((*(byte *)((int)fVar11 + 0x1b) & 1) != 0)) &&
             (uVar4 != 0xffffffff)) {
            iVar7 = 1;
            local_98[0] = uVar4;
          }
          uVar4 = *(uint *)((int)fVar11 + 0x20);
          iVar8 = iVar7;
          if (((-1 < (int)uVar4) && ((*(byte *)((int)fVar11 + 0x1b) & 2) != 0)) &&
             (uVar4 != 0xffffffff)) {
            iVar8 = iVar7 + 1;
            local_98[iVar7] = uVar4;
          }
          uVar4 = *(uint *)((int)fVar11 + 0x24);
          iVar7 = iVar8;
          if (((-1 < (int)uVar4) && ((*(byte *)((int)fVar11 + 0x1b) & 4) != 0)) &&
             (uVar4 != 0xffffffff)) {
            iVar7 = iVar8 + 1;
            local_98[iVar8] = uVar4;
          }
          uVar4 = *(uint *)((int)fVar11 + 0x28);
          iVar8 = iVar7;
          if (((-1 < (int)uVar4) && ((*(byte *)((int)fVar11 + 0x1b) & 8) != 0)) &&
             (uVar4 != 0xffffffff)) {
            iVar8 = iVar7 + 1;
            local_98[iVar7] = uVar4;
          }
          if (iVar8 == 0) {
            uVar4 = 0xffffffff;
          }
          else {
            uVar4 = FUN_80022264(0,iVar8 - 1);
            uVar4 = local_98[uVar4];
          }
        }
        if (uVar4 == 0xffffffff) {
          uVar3 = 1;
        }
        else {
          if ((int)uVar4 < 0) {
            fVar10 = 0.0;
          }
          else {
            fVar11 = (float)(DAT_803de0f0 + -1);
            iVar8 = 0;
            while (iVar8 <= (int)fVar11) {
              iVar7 = (int)fVar11 + iVar8 >> 1;
              fVar10 = (float)(&DAT_803a2448)[iVar7];
              if (*(uint *)((int)fVar10 + 0x14) < uVar4) {
                iVar8 = iVar7 + 1;
              }
              else {
                if (*(uint *)((int)fVar10 + 0x14) <= uVar4) goto LAB_800dffb4;
                fVar11 = (float)(iVar7 + -1);
              }
            }
            fVar10 = 0.0;
          }
LAB_800dffb4:
          param_9[0x29] = fVar10;
          if (fVar10 == 0.0) {
            param_9[0x29] = 0.0;
            uVar3 = 1;
          }
          else {
            if (param_1 != (double)FLOAT_803e12b8) {
              if (param_9[0x20] == 0.0) {
                fVar5 = param_9[0x28];
                fVar1 = *(float *)((int)fVar5 + 8) - *(float *)(param_10 + 0xc);
                fVar2 = *(float *)((int)fVar5 + 0xc) - *(float *)(param_10 + 0x10);
                fVar5 = *(float *)((int)fVar5 + 0x10) - *(float *)(param_10 + 0x14);
              }
              else {
                fVar5 = param_9[0x29];
                fVar1 = *(float *)((int)fVar5 + 8) - *(float *)(param_10 + 0xc);
                fVar2 = *(float *)((int)fVar5 + 0xc) - *(float *)(param_10 + 0x10);
                fVar5 = *(float *)((int)fVar5 + 0x10) - *(float *)(param_10 + 0x14);
              }
              param_3 = (double)fVar2;
              dVar12 = FUN_80293900((double)(fVar5 * fVar5 +
                                            fVar1 * fVar1 + (float)(param_3 * param_3)));
              if (param_1 < dVar12) {
                return 1;
              }
            }
            param_9[0x2e] = *(float *)((int)param_9[0x28] + 8);
            param_9[0x2f] = *(float *)((int)param_9[0x29] + 8);
            uStack_74 = (int)*(char *)((int)param_9[0x28] + 0x2c) << 8 ^ 0x80000000;
            local_78 = 0x43300000;
            dVar12 = (double)FUN_802945e0();
            uStack_6c = (uint)*(byte *)((int)param_9[0x28] + 0x2e);
            local_70 = 0x43300000;
            param_9[0x30] =
                 FLOAT_803e1290 *
                 (float)((double)(float)((double)CONCAT44(0x43300000,uStack_6c) - DOUBLE_803e12a8) *
                        dVar12);
            uStack_64 = (int)*(char *)((int)param_9[0x29] + 0x2c) << 8 ^ 0x80000000;
            local_68 = 0x43300000;
            dVar12 = (double)FUN_802945e0();
            uStack_5c = (uint)*(byte *)((int)param_9[0x29] + 0x2e);
            local_60 = 0x43300000;
            param_9[0x31] =
                 FLOAT_803e1290 *
                 (float)((double)(float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e12a8) *
                        dVar12);
            param_9[0x36] = *(float *)((int)param_9[0x28] + 0xc);
            param_9[0x37] = *(float *)((int)param_9[0x29] + 0xc);
            uStack_54 = (int)*(char *)((int)param_9[0x28] + 0x2d) << 8 ^ 0x80000000;
            local_58 = 0x43300000;
            dVar12 = (double)FUN_802945e0();
            uStack_4c = (uint)*(byte *)((int)param_9[0x28] + 0x2e);
            local_50 = 0x43300000;
            param_9[0x38] =
                 FLOAT_803e1290 *
                 (float)((double)(float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e12a8) *
                        dVar12);
            uStack_44 = (int)*(char *)((int)param_9[0x29] + 0x2d) << 8 ^ 0x80000000;
            local_48 = 0x43300000;
            dVar12 = (double)FUN_802945e0();
            uStack_3c = (uint)*(byte *)((int)param_9[0x29] + 0x2e);
            local_40 = 0x43300000;
            param_9[0x39] =
                 FLOAT_803e1290 *
                 (float)((double)(float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e12a8) *
                        dVar12);
            param_9[0x3e] = *(float *)((int)param_9[0x28] + 0x10);
            param_9[0x3f] = *(float *)((int)param_9[0x29] + 0x10);
            uStack_34 = (int)*(char *)((int)param_9[0x28] + 0x2c) << 8 ^ 0x80000000;
            local_38 = 0x43300000;
            dVar12 = (double)FUN_80294964();
            uStack_2c = (uint)*(byte *)((int)param_9[0x28] + 0x2e);
            local_30 = 0x43300000;
            param_9[0x40] =
                 FLOAT_803e1290 *
                 (float)((double)(float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e12a8) *
                        dVar12);
            uStack_24 = (int)*(char *)((int)param_9[0x29] + 0x2c) << 8 ^ 0x80000000;
            local_28 = 0x43300000;
            dVar13 = (double)FUN_80294964();
            dVar12 = DOUBLE_803e12a8;
            uStack_1c = (uint)*(byte *)((int)param_9[0x29] + 0x2e);
            local_20 = 0x43300000;
            dVar13 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,uStack_1c) -
                                                    DOUBLE_803e12a8) * dVar13);
            param_9[0x41] = (float)((double)FLOAT_803e1290 * dVar13);
            uVar3 = extraout_r4;
            uVar6 = FUN_800df0dc(dVar13,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,
                                 param_9);
            if ((uVar6 & 0xff) == 0) {
              param_9[0x25] = (float)FUN_80010de0;
              param_9[0x26] = (float)&LAB_80010d74;
              param_9[0x21] = (float)(param_9 + 0x2a);
              param_9[0x22] = (float)(param_9 + 0x32);
              param_9[0x23] = (float)(param_9 + 0x3a);
              param_9[0x24] = 1.12104e-44;
              FUN_80010a8c(dVar13,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                           uVar3,iVar8,fVar11,fVar10,uVar4,param_15,param_16);
              uVar3 = 0;
            }
            else {
              uVar3 = 1;
            }
          }
        }
      }
    }
  }
  return uVar3;
}

