// Function: FUN_800df0dc
// Entry: 800df0dc
// Size: 2424 bytes

undefined4
FUN_800df0dc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
            float *param_9)

{
  undefined4 extraout_r4;
  undefined4 extraout_r4_00;
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  float fVar4;
  uint uVar5;
  float fVar6;
  undefined4 in_r9;
  undefined4 in_r10;
  double dVar7;
  double dVar8;
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
  
  if (((param_9 != (float *)0x0) && (param_9[0x28] != 0.0)) && (param_9[0x29] != 0.0)) {
    param_9[0x27] = param_9[0x28];
    param_9[0x28] = param_9[0x29];
    FUN_80003494((uint)(param_9 + 0x2a),(uint)(param_9 + 0x2e),0x10);
    FUN_80003494((uint)(param_9 + 0x32),(uint)(param_9 + 0x36),0x10);
    FUN_80003494((uint)(param_9 + 0x3a),(uint)(param_9 + 0x3e),0x10);
    if (param_9[0x20] == 0.0) {
      fVar4 = param_9[0x28];
      iVar2 = 0;
      uVar5 = *(uint *)((int)fVar4 + 0x1c);
      if (((-1 < (int)uVar5) && ((*(byte *)((int)fVar4 + 0x1b) & 1) == 0)) && (uVar5 != 0xffffffff))
      {
        iVar2 = 1;
        local_88[0] = uVar5;
      }
      uVar5 = *(uint *)((int)fVar4 + 0x20);
      iVar3 = iVar2;
      if (((-1 < (int)uVar5) && ((*(byte *)((int)fVar4 + 0x1b) & 2) == 0)) && (uVar5 != 0xffffffff))
      {
        iVar3 = iVar2 + 1;
        local_88[iVar2] = uVar5;
      }
      uVar5 = *(uint *)((int)fVar4 + 0x24);
      iVar2 = iVar3;
      if (((-1 < (int)uVar5) && ((*(byte *)((int)fVar4 + 0x1b) & 4) == 0)) && (uVar5 != 0xffffffff))
      {
        iVar2 = iVar3 + 1;
        local_88[iVar3] = uVar5;
      }
      uVar5 = *(uint *)((int)fVar4 + 0x28);
      iVar3 = iVar2;
      if (((-1 < (int)uVar5) && ((*(byte *)((int)fVar4 + 0x1b) & 8) == 0)) && (uVar5 != 0xffffffff))
      {
        iVar3 = iVar2 + 1;
        local_88[iVar2] = uVar5;
      }
      if (iVar3 == 0) {
        uVar5 = 0xffffffff;
      }
      else {
        uVar5 = FUN_80022264(0,iVar3 - 1);
        uVar5 = local_88[uVar5];
      }
    }
    else {
      fVar4 = param_9[0x28];
      iVar2 = 0;
      uVar5 = *(uint *)((int)fVar4 + 0x1c);
      if (((-1 < (int)uVar5) && ((*(byte *)((int)fVar4 + 0x1b) & 1) != 0)) && (uVar5 != 0xffffffff))
      {
        iVar2 = 1;
        local_78[0] = uVar5;
      }
      uVar5 = *(uint *)((int)fVar4 + 0x20);
      iVar3 = iVar2;
      if (((-1 < (int)uVar5) && ((*(byte *)((int)fVar4 + 0x1b) & 2) != 0)) && (uVar5 != 0xffffffff))
      {
        iVar3 = iVar2 + 1;
        local_78[iVar2] = uVar5;
      }
      uVar5 = *(uint *)((int)fVar4 + 0x24);
      iVar2 = iVar3;
      if (((-1 < (int)uVar5) && ((*(byte *)((int)fVar4 + 0x1b) & 4) != 0)) && (uVar5 != 0xffffffff))
      {
        iVar2 = iVar3 + 1;
        local_78[iVar3] = uVar5;
      }
      uVar5 = *(uint *)((int)fVar4 + 0x28);
      iVar3 = iVar2;
      if (((-1 < (int)uVar5) && ((*(byte *)((int)fVar4 + 0x1b) & 8) != 0)) && (uVar5 != 0xffffffff))
      {
        iVar3 = iVar2 + 1;
        local_78[iVar2] = uVar5;
      }
      if (iVar3 == 0) {
        uVar5 = 0xffffffff;
      }
      else {
        uVar5 = FUN_80022264(0,iVar3 - 1);
        uVar5 = local_78[uVar5];
      }
    }
    if (uVar5 == 0xffffffff) {
      param_9[0x29] = 0.0;
    }
    else {
      if ((int)uVar5 < 0) {
        fVar6 = 0.0;
      }
      else {
        fVar4 = (float)(DAT_803de0f0 + -1);
        iVar3 = 0;
        while (iVar3 <= (int)fVar4) {
          iVar2 = (int)fVar4 + iVar3 >> 1;
          fVar6 = (float)(&DAT_803a2448)[iVar2];
          if (*(uint *)((int)fVar6 + 0x14) < uVar5) {
            iVar3 = iVar2 + 1;
          }
          else {
            if (*(uint *)((int)fVar6 + 0x14) <= uVar5) goto LAB_800df42c;
            fVar4 = (float)(iVar2 + -1);
          }
        }
        fVar6 = 0.0;
      }
LAB_800df42c:
      param_9[0x29] = fVar6;
      if (param_9[0x29] != 0.0) {
        if (param_9[0x20] == 0.0) {
          param_9[0x2e] = *(float *)((int)param_9[0x28] + 8);
          param_9[0x2f] = *(float *)((int)param_9[0x29] + 8);
          uStack_c = (int)*(char *)((int)param_9[0x28] + 0x2c) << 8 ^ 0x80000000;
          local_10 = 0x43300000;
          dVar7 = (double)FUN_802945e0();
          uStack_14 = (uint)*(byte *)((int)param_9[0x28] + 0x2e);
          local_18 = 0x43300000;
          param_9[0x30] =
               FLOAT_803e1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e12a8) *
                      dVar7);
          uStack_1c = (int)*(char *)((int)param_9[0x29] + 0x2c) << 8 ^ 0x80000000;
          local_20 = 0x43300000;
          dVar7 = (double)FUN_802945e0();
          uStack_24 = (uint)*(byte *)((int)param_9[0x29] + 0x2e);
          local_28 = 0x43300000;
          param_9[0x31] =
               FLOAT_803e1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e12a8) *
                      dVar7);
          param_9[0x36] = *(float *)((int)param_9[0x28] + 0xc);
          param_9[0x37] = *(float *)((int)param_9[0x29] + 0xc);
          uStack_2c = (int)*(char *)((int)param_9[0x28] + 0x2d) << 8 ^ 0x80000000;
          local_30 = 0x43300000;
          dVar7 = (double)FUN_802945e0();
          uStack_34 = (uint)*(byte *)((int)param_9[0x28] + 0x2e);
          local_38 = 0x43300000;
          param_9[0x38] =
               FLOAT_803e1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e12a8) *
                      dVar7);
          uStack_3c = (int)*(char *)((int)param_9[0x29] + 0x2d) << 8 ^ 0x80000000;
          local_40 = 0x43300000;
          dVar7 = (double)FUN_802945e0();
          uStack_44 = (uint)*(byte *)((int)param_9[0x29] + 0x2e);
          local_48 = 0x43300000;
          param_9[0x39] =
               FLOAT_803e1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e12a8) *
                      dVar7);
          param_9[0x3e] = *(float *)((int)param_9[0x28] + 0x10);
          param_9[0x3f] = *(float *)((int)param_9[0x29] + 0x10);
          uStack_4c = (int)*(char *)((int)param_9[0x28] + 0x2c) << 8 ^ 0x80000000;
          local_50 = 0x43300000;
          dVar7 = (double)FUN_80294964();
          uStack_54 = (uint)*(byte *)((int)param_9[0x28] + 0x2e);
          local_58 = 0x43300000;
          param_9[0x40] =
               FLOAT_803e1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e12a8) *
                      dVar7);
          uStack_5c = (int)*(char *)((int)param_9[0x29] + 0x2c) << 8 ^ 0x80000000;
          local_60 = 0x43300000;
          dVar8 = (double)FUN_80294964();
          dVar7 = DOUBLE_803e12a8;
          uStack_64 = (uint)*(byte *)((int)param_9[0x29] + 0x2e);
          local_68 = 0x43300000;
          dVar8 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,uStack_64) -
                                                 DOUBLE_803e12a8) * dVar8);
          param_9[0x41] = (float)((double)FLOAT_803e1290 * dVar8);
          uVar1 = extraout_r4_00;
        }
        else {
          param_9[0x2e] = *(float *)((int)param_9[0x28] + 8);
          param_9[0x2f] = *(float *)((int)param_9[0x27] + 8);
          uStack_64 = (int)*(char *)((int)param_9[0x28] + 0x2c) << 8 ^ 0x80000000;
          local_68 = 0x43300000;
          dVar7 = (double)FUN_802945e0();
          uStack_5c = (uint)*(byte *)((int)param_9[0x28] + 0x2e);
          local_60 = 0x43300000;
          param_9[0x30] =
               FLOAT_803e1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e12a8) *
                      dVar7);
          uStack_54 = (int)*(char *)((int)param_9[0x27] + 0x2c) << 8 ^ 0x80000000;
          local_58 = 0x43300000;
          dVar7 = (double)FUN_802945e0();
          uStack_4c = (uint)*(byte *)((int)param_9[0x27] + 0x2e);
          local_50 = 0x43300000;
          param_9[0x31] =
               FLOAT_803e1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e12a8) *
                      dVar7);
          param_9[0x36] = *(float *)((int)param_9[0x28] + 0xc);
          param_9[0x37] = *(float *)((int)param_9[0x27] + 0xc);
          uStack_44 = (int)*(char *)((int)param_9[0x28] + 0x2d) << 8 ^ 0x80000000;
          local_48 = 0x43300000;
          dVar7 = (double)FUN_802945e0();
          uStack_3c = (uint)*(byte *)((int)param_9[0x28] + 0x2e);
          local_40 = 0x43300000;
          param_9[0x38] =
               FLOAT_803e1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e12a8) *
                      dVar7);
          uStack_34 = (int)*(char *)((int)param_9[0x27] + 0x2d) << 8 ^ 0x80000000;
          local_38 = 0x43300000;
          dVar7 = (double)FUN_802945e0();
          uStack_2c = (uint)*(byte *)((int)param_9[0x27] + 0x2e);
          local_30 = 0x43300000;
          param_9[0x39] =
               FLOAT_803e1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e12a8) *
                      dVar7);
          param_9[0x3e] = *(float *)((int)param_9[0x28] + 0x10);
          param_9[0x3f] = *(float *)((int)param_9[0x27] + 0x10);
          uStack_24 = (int)*(char *)((int)param_9[0x28] + 0x2c) << 8 ^ 0x80000000;
          local_28 = 0x43300000;
          dVar7 = (double)FUN_80294964();
          uStack_1c = (uint)*(byte *)((int)param_9[0x28] + 0x2e);
          local_20 = 0x43300000;
          param_9[0x40] =
               FLOAT_803e1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e12a8) *
                      dVar7);
          uStack_14 = (int)*(char *)((int)param_9[0x27] + 0x2c) << 8 ^ 0x80000000;
          local_18 = 0x43300000;
          dVar8 = (double)FUN_80294964();
          dVar7 = DOUBLE_803e12a8;
          uStack_c = (uint)*(byte *)((int)param_9[0x27] + 0x2e);
          local_10 = 0x43300000;
          dVar8 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,uStack_c) -
                                                 DOUBLE_803e12a8) * dVar8);
          param_9[0x41] = (float)((double)FLOAT_803e1290 * dVar8);
          uVar1 = extraout_r4;
        }
        if (param_9[0x24] != 0.0) {
          FUN_80010924(dVar8,dVar7,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9,
                       uVar1,iVar3,fVar4,fVar6,uVar5,in_r9,in_r10);
        }
        if (param_9[0x20] == 0.0) {
          FUN_80010340((double)FLOAT_803e12b4,param_9);
        }
        else {
          FUN_80010340((double)FLOAT_803e12b0,param_9);
        }
        return 0;
      }
    }
  }
  return 1;
}

