// Function: FUN_800dd8cc
// Entry: 800dd8cc
// Size: 2196 bytes

undefined4
FUN_800dd8cc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
            float *param_9,undefined4 param_10,uint param_11)

{
  undefined4 uVar1;
  uint uVar2;
  int iVar3;
  undefined4 extraout_r4;
  int iVar4;
  int iVar5;
  uint uVar6;
  float fVar7;
  float fVar8;
  undefined4 in_r9;
  undefined4 in_r10;
  double dVar9;
  double dVar10;
  uint local_98 [4];
  uint local_88 [4];
  uint local_78 [4];
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
  undefined4 local_18;
  uint uStack_14;
  undefined4 local_10;
  uint uStack_c;
  
  if (param_9 == (float *)0x0) {
    uVar1 = 1;
  }
  else if (param_11 == 0xffffffff) {
    uVar1 = 1;
  }
  else {
    if (param_9[0x20] != 0.0) {
      if ((int)param_11 < 0) {
        fVar8 = 0.0;
      }
      else {
        iVar5 = DAT_803de0f0 + -1;
        iVar4 = 0;
        while (iVar4 <= iVar5) {
          iVar3 = iVar5 + iVar4 >> 1;
          fVar8 = (float)(&DAT_803a2448)[iVar3];
          if (*(uint *)((int)fVar8 + 0x14) < param_11) {
            iVar4 = iVar3 + 1;
          }
          else {
            if (*(uint *)((int)fVar8 + 0x14) <= param_11) goto LAB_800dd96c;
            iVar5 = iVar3 + -1;
          }
        }
        fVar8 = 0.0;
      }
LAB_800dd96c:
      param_9[0x28] = fVar8;
      fVar8 = param_9[0x28];
      iVar4 = 0;
      uVar6 = *(uint *)((int)fVar8 + 0x1c);
      if (((-1 < (int)uVar6) && ((*(byte *)((int)fVar8 + 0x1b) & 1) == 0)) && (uVar6 != 0xffffffff))
      {
        iVar4 = 1;
        local_78[0] = uVar6;
      }
      uVar6 = *(uint *)((int)fVar8 + 0x20);
      iVar5 = iVar4;
      if (((-1 < (int)uVar6) && ((*(byte *)((int)fVar8 + 0x1b) & 2) == 0)) && (uVar6 != 0xffffffff))
      {
        iVar5 = iVar4 + 1;
        local_78[iVar4] = uVar6;
      }
      uVar6 = *(uint *)((int)fVar8 + 0x24);
      iVar4 = iVar5;
      if (((-1 < (int)uVar6) && ((*(byte *)((int)fVar8 + 0x1b) & 4) == 0)) && (uVar6 != 0xffffffff))
      {
        iVar4 = iVar5 + 1;
        local_78[iVar5] = uVar6;
      }
      uVar6 = *(uint *)((int)fVar8 + 0x28);
      iVar5 = iVar4;
      if (((-1 < (int)uVar6) && ((*(byte *)((int)fVar8 + 0x1b) & 8) == 0)) && (uVar6 != 0xffffffff))
      {
        iVar5 = iVar4 + 1;
        local_78[iVar4] = uVar6;
      }
      if (iVar5 == 0) {
        param_11 = 0xffffffff;
      }
      else {
        uVar6 = FUN_80022264(0,iVar5 - 1);
        param_11 = local_78[uVar6];
      }
      if (param_11 == 0xffffffff) {
        return 1;
      }
    }
    if ((int)param_11 < 0) {
      fVar8 = 0.0;
    }
    else {
      iVar5 = DAT_803de0f0 + -1;
      iVar4 = 0;
      while (iVar4 <= iVar5) {
        iVar3 = iVar5 + iVar4 >> 1;
        fVar8 = (float)(&DAT_803a2448)[iVar3];
        if (*(uint *)((int)fVar8 + 0x14) < param_11) {
          iVar4 = iVar3 + 1;
        }
        else {
          if (*(uint *)((int)fVar8 + 0x14) <= param_11) goto LAB_800ddb0c;
          iVar5 = iVar3 + -1;
        }
      }
      fVar8 = 0.0;
    }
LAB_800ddb0c:
    param_9[0x28] = fVar8;
    if (fVar8 == 0.0) {
      param_9[0x28] = 0.0;
      uVar1 = 1;
    }
    else {
      if (param_9[0x20] == 0.0) {
        fVar8 = param_9[0x28];
        iVar4 = 0;
        uVar6 = *(uint *)((int)fVar8 + 0x1c);
        if (((-1 < (int)uVar6) && ((*(byte *)((int)fVar8 + 0x1b) & 1) == 0)) &&
           (uVar6 != 0xffffffff)) {
          iVar4 = 1;
          local_98[0] = uVar6;
        }
        uVar6 = *(uint *)((int)fVar8 + 0x20);
        iVar5 = iVar4;
        if (((-1 < (int)uVar6) && ((*(byte *)((int)fVar8 + 0x1b) & 2) == 0)) &&
           (uVar6 != 0xffffffff)) {
          iVar5 = iVar4 + 1;
          local_98[iVar4] = uVar6;
        }
        uVar6 = *(uint *)((int)fVar8 + 0x24);
        iVar4 = iVar5;
        if (((-1 < (int)uVar6) && ((*(byte *)((int)fVar8 + 0x1b) & 4) == 0)) &&
           (uVar6 != 0xffffffff)) {
          iVar4 = iVar5 + 1;
          local_98[iVar5] = uVar6;
        }
        uVar6 = *(uint *)((int)fVar8 + 0x28);
        iVar5 = iVar4;
        if (((-1 < (int)uVar6) && ((*(byte *)((int)fVar8 + 0x1b) & 8) == 0)) &&
           (uVar6 != 0xffffffff)) {
          iVar5 = iVar4 + 1;
          local_98[iVar4] = uVar6;
        }
        if (iVar5 == 0) {
          uVar6 = 0xffffffff;
        }
        else {
          uVar6 = FUN_80022264(0,iVar5 - 1);
          uVar6 = local_98[uVar6];
        }
      }
      else {
        fVar8 = param_9[0x28];
        iVar4 = 0;
        uVar6 = *(uint *)((int)fVar8 + 0x1c);
        if (((-1 < (int)uVar6) && ((*(byte *)((int)fVar8 + 0x1b) & 1) != 0)) &&
           (uVar6 != 0xffffffff)) {
          iVar4 = 1;
          local_88[0] = uVar6;
        }
        uVar6 = *(uint *)((int)fVar8 + 0x20);
        iVar5 = iVar4;
        if (((-1 < (int)uVar6) && ((*(byte *)((int)fVar8 + 0x1b) & 2) != 0)) &&
           (uVar6 != 0xffffffff)) {
          iVar5 = iVar4 + 1;
          local_88[iVar4] = uVar6;
        }
        uVar6 = *(uint *)((int)fVar8 + 0x24);
        iVar4 = iVar5;
        if (((-1 < (int)uVar6) && ((*(byte *)((int)fVar8 + 0x1b) & 4) != 0)) &&
           (uVar6 != 0xffffffff)) {
          iVar4 = iVar5 + 1;
          local_88[iVar5] = uVar6;
        }
        uVar6 = *(uint *)((int)fVar8 + 0x28);
        iVar5 = iVar4;
        if (((-1 < (int)uVar6) && ((*(byte *)((int)fVar8 + 0x1b) & 8) != 0)) &&
           (uVar6 != 0xffffffff)) {
          iVar5 = iVar4 + 1;
          local_88[iVar4] = uVar6;
        }
        if (iVar5 == 0) {
          uVar6 = 0xffffffff;
        }
        else {
          uVar6 = FUN_80022264(0,iVar5 - 1);
          uVar6 = local_88[uVar6];
        }
      }
      if (uVar6 == 0xffffffff) {
        uVar1 = 1;
      }
      else {
        if ((int)uVar6 < 0) {
          fVar7 = 0.0;
        }
        else {
          fVar8 = (float)(DAT_803de0f0 + -1);
          iVar5 = 0;
          while (iVar5 <= (int)fVar8) {
            iVar4 = (int)fVar8 + iVar5 >> 1;
            fVar7 = (float)(&DAT_803a2448)[iVar4];
            if (*(uint *)((int)fVar7 + 0x14) < uVar6) {
              iVar5 = iVar4 + 1;
            }
            else {
              if (*(uint *)((int)fVar7 + 0x14) <= uVar6) goto LAB_800dde00;
              fVar8 = (float)(iVar4 + -1);
            }
          }
          fVar7 = 0.0;
        }
LAB_800dde00:
        param_9[0x29] = fVar7;
        if (fVar7 == 0.0) {
          param_9[0x29] = 0.0;
          uVar1 = 1;
        }
        else {
          param_9[0x2e] = *(float *)((int)param_9[0x28] + 8);
          param_9[0x2f] = *(float *)((int)param_9[0x29] + 8);
          uStack_64 = (int)*(char *)((int)param_9[0x28] + 0x2c) << 8 ^ 0x80000000;
          local_68 = 0x43300000;
          dVar9 = (double)FUN_802945e0();
          uStack_5c = (uint)*(byte *)((int)param_9[0x28] + 0x2e);
          local_60 = 0x43300000;
          param_9[0x30] =
               FLOAT_803e1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e12a8) *
                      dVar9);
          uStack_54 = (int)*(char *)((int)param_9[0x29] + 0x2c) << 8 ^ 0x80000000;
          local_58 = 0x43300000;
          dVar9 = (double)FUN_802945e0();
          uStack_4c = (uint)*(byte *)((int)param_9[0x29] + 0x2e);
          local_50 = 0x43300000;
          param_9[0x31] =
               FLOAT_803e1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e12a8) *
                      dVar9);
          param_9[0x36] = *(float *)((int)param_9[0x28] + 0xc);
          param_9[0x37] = *(float *)((int)param_9[0x29] + 0xc);
          uStack_44 = (int)*(char *)((int)param_9[0x28] + 0x2d) << 8 ^ 0x80000000;
          local_48 = 0x43300000;
          dVar9 = (double)FUN_802945e0();
          uStack_3c = (uint)*(byte *)((int)param_9[0x28] + 0x2e);
          local_40 = 0x43300000;
          param_9[0x38] =
               FLOAT_803e1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e12a8) *
                      dVar9);
          uStack_34 = (int)*(char *)((int)param_9[0x29] + 0x2d) << 8 ^ 0x80000000;
          local_38 = 0x43300000;
          dVar9 = (double)FUN_802945e0();
          uStack_2c = (uint)*(byte *)((int)param_9[0x29] + 0x2e);
          local_30 = 0x43300000;
          param_9[0x39] =
               FLOAT_803e1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e12a8) *
                      dVar9);
          param_9[0x3e] = *(float *)((int)param_9[0x28] + 0x10);
          param_9[0x3f] = *(float *)((int)param_9[0x29] + 0x10);
          uStack_24 = (int)*(char *)((int)param_9[0x28] + 0x2c) << 8 ^ 0x80000000;
          local_28 = 0x43300000;
          dVar9 = (double)FUN_80294964();
          uStack_1c = (uint)*(byte *)((int)param_9[0x28] + 0x2e);
          local_20 = 0x43300000;
          param_9[0x40] =
               FLOAT_803e1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e12a8) *
                      dVar9);
          uStack_14 = (int)*(char *)((int)param_9[0x29] + 0x2c) << 8 ^ 0x80000000;
          local_18 = 0x43300000;
          dVar10 = (double)FUN_80294964();
          dVar9 = DOUBLE_803e12a8;
          uStack_c = (uint)*(byte *)((int)param_9[0x29] + 0x2e);
          local_10 = 0x43300000;
          dVar10 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,uStack_c) -
                                                  DOUBLE_803e12a8) * dVar10);
          param_9[0x41] = (float)((double)FLOAT_803e1290 * dVar10);
          uVar1 = extraout_r4;
          uVar2 = FUN_800df0dc(dVar10,dVar9,param_3,param_4,param_5,param_6,param_7,param_8,param_9)
          ;
          if ((uVar2 & 0xff) == 0) {
            param_9[0x25] = (float)FUN_80010de0;
            param_9[0x26] = (float)&LAB_80010d74;
            param_9[0x21] = (float)(param_9 + 0x2a);
            param_9[0x22] = (float)(param_9 + 0x32);
            param_9[0x23] = (float)(param_9 + 0x3a);
            param_9[0x24] = 1.12104e-44;
            FUN_80010a8c(dVar10,dVar9,param_3,param_4,param_5,param_6,param_7,param_8,param_9,uVar1,
                         iVar5,fVar8,fVar7,uVar6,in_r9,in_r10);
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

