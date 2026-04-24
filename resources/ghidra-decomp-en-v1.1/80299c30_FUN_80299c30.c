// Function: FUN_80299c30
// Entry: 80299c30
// Size: 1760 bytes

/* WARNING: Removing unreachable block (ram,0x8029a2e8) */
/* WARNING: Removing unreachable block (ram,0x80299c40) */

undefined4
FUN_80299c30(double param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int *param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  short sVar3;
  int iVar2;
  ushort uVar4;
  int iVar5;
  double dVar6;
  short local_b0 [2];
  undefined2 local_ac;
  undefined local_aa;
  undefined local_a9;
  float local_a8;
  float local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  float local_94;
  int aiStack_90 [15];
  float local_54;
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  
  iVar5 = param_9[0x2e];
  if (*(char *)((int)param_10 + 0x27a) != '\0') {
    FUN_80035f84((int)param_9);
  }
  sVar3 = FUN_8011f68c(local_b0);
  if ((sVar3 == 1) && (local_b0[0] == 0x957)) {
    uVar4 = 0x900;
  }
  else {
    uVar4 = 0x100;
  }
  *param_10 = *param_10 | 0x200000;
  fVar1 = FLOAT_803e8b3c;
  sVar3 = *(short *)(param_9 + 0x28);
  if (sVar3 == 0x7f) {
    param_9[10] = (int)(float)((double)FLOAT_803e8b94 * param_1 + (double)(float)param_9[10]);
    if (FLOAT_803e8ba8 < (float)param_9[10]) {
      param_9[10] = (int)FLOAT_803e8ba8;
    }
    if (FLOAT_803df110 < (float)param_9[4]) {
      FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0x80,0,param_12,param_13,param_14,param_15,param_16);
      param_10[0xa8] = (uint)FLOAT_803e8c1c;
    }
  }
  else {
    if (sVar3 < 0x7f) {
      if (sVar3 == 0x43) {
        if ((*(ushort *)(iVar5 + 0x6e0) & uVar4) != 0) {
          FUN_8000bb38((uint)param_9,0x216);
          FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,
                       param_8,param_9,0x87,0,param_12,param_13,param_14,param_15,param_16);
          param_10[0xa8] = (uint)FLOAT_803e8b90;
          return 0;
        }
        if ((*(ushort *)(iVar5 + 0x6e2) & 0x200) == 0) {
          return 0;
        }
        FUN_80014b68(0,0x200);
        FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,0x44,0,param_12,param_13,param_14,param_15,param_16);
        param_10[0xa8] = (uint)FLOAT_803e8c18;
        return 0;
      }
      if (sVar3 < 0x43) {
        if (sVar3 == 4) {
          if ((DAT_803df10d == '\0') && (FLOAT_803e8c0c < (float)param_9[0x26])) {
            FUN_8000bb38((uint)param_9,0x215);
            DAT_803df10d = '\x01';
          }
          if (*(char *)((int)param_10 + 0x346) == '\0') {
            return 0;
          }
          if ((*(ushort *)(iVar5 + 0x6e0) & uVar4) != 0) {
            FUN_8000bb38((uint)param_9,0x216);
            FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,param_9,0x87,0,param_12,param_13,param_14,param_15,param_16);
            param_10[0xa8] = (uint)FLOAT_803e8b90;
            return 0;
          }
          FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,
                       param_8,param_9,0x43,0,param_12,param_13,param_14,param_15,param_16);
          param_10[0xa8] = (uint)FLOAT_803e8c10;
          return 0;
        }
      }
      else if (sVar3 < 0x45) {
        if (*(char *)((int)param_10 + 0x346) == '\0') {
          return 0;
        }
        *(uint *)(iVar5 + 0x360) = *(uint *)(iVar5 + 0x360) | 0x800000;
        param_9[10] = (int)FLOAT_803e8b3c;
        *(undefined2 *)(iVar5 + 0x80a) = 0xffff;
        param_10[0xc2] = (uint)FUN_802a58ac;
        return 2;
      }
    }
    else {
      if (sVar3 == 0x87) {
        if ((*(ushort *)(iVar5 + 0x6e0) & uVar4) != 0) {
          param_2 = (double)*(float *)(iVar5 + 0x7d4);
          uStack_34 = (int)*(short *)(*(int *)(param_9[0x2e] + 0x35c) + 4) ^ 0x80000000;
          local_38 = 0x43300000;
          if (param_2 <= (double)(float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e8b58))
          {
            param_10[0xa8] =
                 (uint)(float)((double)FLOAT_803e8bb8 * param_1 + (double)(float)param_10[0xa8]);
            if (FLOAT_803e8c04 < (float)param_10[0xa8]) {
              param_10[0xa8] = (uint)FLOAT_803e8c04;
            }
            *(float *)(iVar5 + 0x7d4) =
                 (float)((double)FLOAT_803e8c14 * param_1 + (double)*(float *)(iVar5 + 0x7d4));
            *(float *)(iVar5 + 0x7d4) =
                 (float)((double)FLOAT_803e8b30 * param_1 + (double)*(float *)(iVar5 + 0x7d4));
            if (*(float *)(iVar5 + 0x7d4) < FLOAT_803e8b70) {
              return 0;
            }
            *(float *)(iVar5 + 0x7d4) = FLOAT_803e8b3c;
            iVar2 = *(int *)(param_9[0x2e] + 0x35c);
            iVar5 = *(short *)(iVar2 + 4) + -10;
            if (iVar5 < 0) {
              iVar5 = 0;
            }
            else if (*(short *)(iVar2 + 6) < iVar5) {
              iVar5 = (int)*(short *)(iVar2 + 6);
            }
            *(short *)(iVar2 + 4) = (short)iVar5;
            FUN_8000bb38((uint)param_9,0x217);
            FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,param_9,0x88,0,param_12,param_13,param_14,param_15,param_16);
            param_10[0xa8] = (uint)FLOAT_803e8c04;
            return 0;
          }
        }
        FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,0x43,0,param_12,param_13,param_14,param_15,param_16);
        param_10[0xa8] = (uint)FLOAT_803e8c10;
        return 0;
      }
      if (sVar3 < 0x87) {
        if (sVar3 < 0x81) {
          param_9[10] = (int)(float)-(DOUBLE_803e8c20 * param_1 - (double)(float)param_9[10]);
          dVar6 = (double)FUN_802932a4((double)FLOAT_803e8c28,param_1);
          param_9[10] = (int)(float)((double)(float)param_9[10] * dVar6);
          (**(code **)(*DAT_803dd70c + 0x20))(param_1,param_9,param_10,1);
          if (*(char *)((int)param_10 + 0x346) == '\0') {
            return 0;
          }
          *(uint *)(iVar5 + 0x360) = *(uint *)(iVar5 + 0x360) | 0x800000;
          param_9[10] = (int)FLOAT_803e8b3c;
          *(undefined2 *)(iVar5 + 0x80a) = 0xffff;
          param_10[0xc2] = (uint)FUN_802a58ac;
          return 2;
        }
      }
      else if (sVar3 < 0x89) {
        param_9[10] = (int)(float)((double)FLOAT_803e8c04 * param_1 + (double)(float)param_9[10]);
        if (*(char *)((int)param_10 + 0x346) == '\0') {
          return 0;
        }
        iVar5 = FUN_8002ba84();
        if (iVar5 != 0) {
          FUN_80139280(iVar5);
        }
        FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,0x7f,0,param_12,param_13,param_14,param_15,param_16);
        param_10[0xa8] = (uint)FLOAT_803e8b4c;
        return 0;
      }
    }
    dVar6 = (double)FLOAT_803e8b3c;
    param_10[0xa5] = (uint)FLOAT_803e8b3c;
    param_10[0xa1] = (uint)fVar1;
    param_10[0xa0] = (uint)fVar1;
    param_9[9] = (int)fVar1;
    param_9[10] = (int)fVar1;
    param_9[0xb] = (int)fVar1;
    FUN_8003042c(dVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,4,0,param_12,
                 param_13,param_14,param_15,param_16);
    param_10[0xa8] = (uint)FLOAT_803e8c1c;
    FLOAT_803df114 = (float)param_9[4];
    *(undefined2 *)(iVar5 + 0x478) = *DAT_803df0b4;
    *(undefined2 *)(iVar5 + 0x484) = *(undefined2 *)(iVar5 + 0x478);
    FUN_8018a4b4((int)DAT_803df0b4,(float *)(param_9 + 3),(float *)(param_9 + 5));
    FUN_802abd04((int)param_9,iVar5,7);
    param_10[1] = param_10[1] | 0x8000000;
    local_9c = (float)param_9[3];
    local_98 = FLOAT_803e8b70 + (float)param_9[4];
    local_94 = (float)param_9[5];
    uStack_34 = (int)*(short *)(iVar5 + 0x478) ^ 0x80000000;
    local_38 = 0x43300000;
    dVar6 = (double)FUN_802945e0();
    local_a8 = -(float)((double)FLOAT_803e8bf4 * dVar6 - (double)local_9c);
    local_a4 = local_98;
    uStack_2c = (int)*(short *)(iVar5 + 0x478) ^ 0x80000000;
    local_30 = 0x43300000;
    dVar6 = (double)FUN_80294964();
    local_a0 = -(float)((double)FLOAT_803e8bf4 * dVar6 - (double)local_94);
    iVar2 = FUN_80064248(&local_9c,&local_a8,(float *)0x3,aiStack_90,param_9,1,1,0xff,0);
    if (iVar2 == 0) {
      FLOAT_803df110 = FLOAT_803e8bf4 + (float)param_9[4];
    }
    else {
      FLOAT_803df110 = local_54 - FLOAT_803e8bc8;
    }
    DAT_803df10d = '\0';
    if ((DAT_803df0cc != 0) && ((*(byte *)(iVar5 + 0x3f4) >> 6 & 1) != 0)) {
      *(undefined *)(iVar5 + 0x8b4) = 4;
      *(byte *)(iVar5 + 0x3f4) = *(byte *)(iVar5 + 0x3f4) & 0xf7 | 8;
    }
    *(float *)(iVar5 + 0x7d4) = FLOAT_803e8b3c;
    if ((*(char *)(iVar5 + 0x8c8) != 'H') && (*(char *)(iVar5 + 0x8c8) != 'G')) {
      local_ac = 0;
      local_aa = 0;
      local_a9 = 1;
      (**(code **)(*DAT_803dd6d0 + 0x1c))(0x43,1,0,4,&local_ac,0,0xff);
    }
  }
  return 0;
}

