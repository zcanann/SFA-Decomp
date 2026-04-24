// Function: FUN_802995b4
// Entry: 802995b4
// Size: 1616 bytes

/* WARNING: Removing unreachable block (ram,0x80299bdc) */
/* WARNING: Removing unreachable block (ram,0x80299874) */
/* WARNING: Removing unreachable block (ram,0x802995c4) */

undefined4
FUN_802995b4(double param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  short sVar1;
  float fVar2;
  ushort uVar3;
  int iVar4;
  byte bVar6;
  uint uVar5;
  uint uVar7;
  int iVar8;
  double dVar9;
  undefined2 local_38;
  undefined local_36;
  undefined local_35;
  undefined4 local_30;
  uint uStack_2c;
  undefined8 local_28;
  
  iVar8 = *(int *)(param_9 + 0xb8);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_80035f84(param_9);
  }
  FUN_8011f6ac(10);
  fVar2 = FLOAT_803e8b3c;
  *(float *)(param_10 + 0x294) = FLOAT_803e8b3c;
  *(float *)(param_10 + 0x284) = fVar2;
  *(float *)(param_10 + 0x280) = fVar2;
  *(float *)(param_9 + 0x24) = fVar2;
  *(float *)(param_9 + 0x28) = fVar2;
  *(float *)(param_9 + 0x2c) = fVar2;
  sVar1 = *(short *)(param_9 + 0xa0);
  if (sVar1 == 0xb1) {
    FUN_8011f6d0(2);
    FUN_8018a764((int)DAT_803df0b4,0);
    if ((*(ushort *)(iVar8 + 0x6e2) & 0x100) != 0) {
      FUN_80014b68(0,0x100);
      FLOAT_803df108 = FLOAT_803e8b70;
      FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0xac,0,param_12,param_13,param_14,param_15,param_16);
      *(float *)(param_10 + 0x2a0) = FLOAT_803e8b3c;
      return 0;
    }
    if ((*(ushort *)(iVar8 + 0x6e2) & 0x200) == 0) {
      return 0;
    }
    FUN_80014b68(0,0x200);
    FUN_8000bb38(param_9,0x218);
    FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0xd1,0,param_12,param_13,param_14,param_15,param_16);
    *(float *)(param_10 + 0x2a0) = FLOAT_803e8be4;
    return 0;
  }
  if (0xb0 < sVar1) {
    if (sVar1 == 0xd0) {
      FUN_8018a764((int)DAT_803df0b4,0x800);
      if (*(char *)(param_10 + 0x346) == '\0') {
        return 0;
      }
      FUN_8000bb38(param_9,0x109);
      FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0xb2,0,param_12,param_13,param_14,param_15,param_16);
      *(float *)(param_10 + 0x2a0) = FLOAT_803e8b90;
      return 0;
    }
    if (sVar1 < 0xd0) {
      if (sVar1 < 0xb3) {
        FUN_8018a764((int)DAT_803df0b4,0x800);
        if ((*(ushort *)(iVar8 + 0x6e2) & 0x200) == 0) {
          return 0;
        }
        FUN_80014b68(0,0x200);
        FUN_8000bb38(param_9,0x218);
        FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,0xad,0,param_12,param_13,param_14,param_15,param_16);
        *(float *)(param_10 + 0x2a0) = FLOAT_803e8be4;
        return 0;
      }
    }
    else if (sVar1 < 0xd2) {
      if (*(char *)(param_10 + 0x346) == '\0') {
        return 0;
      }
      *(uint *)(iVar8 + 0x360) = *(uint *)(iVar8 + 0x360) | 0x800000;
      *(code **)(param_10 + 0x308) = FUN_802a58ac;
      return 2;
    }
LAB_80299af0:
    FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0xab,0,param_12,param_13,param_14,param_15,param_16);
    *(float *)(param_10 + 0x2a0) = FLOAT_803e8bd8;
    FUN_8018a4b4((int)DAT_803df0b4,(float *)(param_9 + 0xc),(float *)(param_9 + 0x14));
    *(short *)(iVar8 + 0x478) = *DAT_803df0b4 + -0x8000;
    *(undefined2 *)(iVar8 + 0x484) = *(undefined2 *)(iVar8 + 0x478);
    if ((DAT_803df0cc != 0) && ((*(byte *)(iVar8 + 0x3f4) >> 6 & 1) != 0)) {
      *(undefined *)(iVar8 + 0x8b4) = 4;
      *(byte *)(iVar8 + 0x3f4) = *(byte *)(iVar8 + 0x3f4) & 0xf7 | 8;
    }
    FLOAT_803df108 = FLOAT_803e8b3c;
    DAT_803df10c = 0;
    FLOAT_803df0e0 = FLOAT_803e8b3c;
    if ((*(char *)(iVar8 + 0x8c8) != 'H') && (*(char *)(iVar8 + 0x8c8) != 'G')) {
      local_38 = 0;
      local_36 = 0;
      local_35 = 1;
      (**(code **)(*DAT_803dd6d0 + 0x1c))(0x43,1,0,4,&local_38,0,0xff);
    }
    return 0;
  }
  if (sVar1 != 0xac) {
    if (sVar1 < 0xac) {
      if (0xaa < sVar1) {
        FUN_8011f6d0(2);
        if ((DAT_803df10c == '\0') && (FLOAT_803e8b34 < *(float *)(param_9 + 0x98))) {
          FUN_8000bb38(param_9,0x218);
          DAT_803df10c = '\x01';
        }
        if (*(char *)(param_10 + 0x346) == '\0') {
          return 0;
        }
        FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,0xb1,0,param_12,param_13,param_14,param_15,param_16);
        *(float *)(param_10 + 0x2a0) = FLOAT_803e8b90;
        return 0;
      }
    }
    else if (sVar1 < 0xae) {
      if (*(char *)(param_10 + 0x346) == '\0') {
        return 0;
      }
      *(uint *)(iVar8 + 0x360) = *(uint *)(iVar8 + 0x360) | 0x800000;
      *(code **)(param_10 + 0x308) = FUN_802a58ac;
      return 2;
    }
    goto LAB_80299af0;
  }
  FUN_8011f6d0(2);
  FLOAT_803df108 = FLOAT_803df108 - FLOAT_803e8b78;
  if (((*(ushort *)(iVar8 + 0x6e4) & 0x100) == 0) && (iVar4 = FUN_80080490(), iVar4 == 0))
  goto LAB_802998b8;
  FUN_80014b68(0,0x100);
  FLOAT_803df0e0 = (float)((double)FLOAT_803df0e0 - param_1);
  if (FLOAT_803df0e0 < FLOAT_803e8b3c) {
    if (*(short *)(iVar8 + 0x81a) == 0) {
      uVar3 = 0x2d3;
    }
    else {
      uVar3 = 0x2b;
    }
    FUN_8000bb38(param_9,uVar3);
    uStack_2c = FUN_80022264(10,0x12);
    uStack_2c = uStack_2c ^ 0x80000000;
    local_30 = 0x43300000;
    FLOAT_803df0e0 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e8b58);
  }
  bVar6 = FUN_8018a49c((int)DAT_803df0b4);
  if (bVar6 != 1) {
    if (bVar6 == 0) {
      FLOAT_803df108 = FLOAT_803df108 + FLOAT_803e8bf0;
      goto LAB_802998b8;
    }
    if (bVar6 < 3) {
      FLOAT_803df108 = FLOAT_803df108 + FLOAT_803e8be8;
      goto LAB_802998b8;
    }
  }
  FLOAT_803df108 = FLOAT_803df108 + FLOAT_803e8bec;
LAB_802998b8:
  if (FLOAT_803df108 <= FLOAT_803e8bf4) {
    if (FLOAT_803df108 < FLOAT_803e8bf8) {
      FLOAT_803df108 = FLOAT_803e8bf8;
    }
  }
  else {
    FLOAT_803df108 = FLOAT_803e8bf4;
  }
  uStack_2c = FUN_8018a758((int)DAT_803df0b4);
  uStack_2c = uStack_2c ^ 0x80000000;
  local_30 = 0x43300000;
  uVar7 = (uint)((float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e8b58) + FLOAT_803df108)
  ;
  local_28 = (double)(longlong)(int)uVar7;
  if ((int)uVar7 < 1) {
    FLOAT_803df108 = FLOAT_803e8b3c;
    uVar7 = 0;
    FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0xb1,0,param_12,param_13,param_14,param_15,param_16);
    *(float *)(param_10 + 0x2a0) = FLOAT_803e8b90;
  }
  else if (0x800 < (int)uVar7) {
    uVar7 = 0x800;
  }
  local_28 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
  dVar9 = (double)(float)((double)(float)(local_28 - DOUBLE_803e8b58) / (double)FLOAT_803e8bfc);
  if (dVar9 < (double)FLOAT_803e8c00) {
    uVar5 = FUN_80022264(0xffffff9c,100);
    local_28 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
    FUN_800303fc((double)(float)(dVar9 + (double)((float)(local_28 - DOUBLE_803e8b58) /
                                                 FLOAT_803e8c08)),param_9);
  }
  else {
    FUN_8018a1c0((double)(float)(local_28 - DOUBLE_803e8b58),param_2,param_3,param_4,param_5,param_6
                 ,param_7,param_8);
    if (*(short *)(iVar8 + 0x81a) == 0) {
      uVar3 = 0x2d3;
    }
    else {
      uVar3 = 0x2b;
    }
    FUN_8000bb38(param_9,uVar3);
    FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0xd0,0,param_12,param_13,param_14,param_15,param_16);
    *(float *)(param_10 + 0x2a0) = FLOAT_803e8c04;
  }
  FUN_8018a764((int)DAT_803df0b4,uVar7);
  return 0;
}

