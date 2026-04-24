// Function: FUN_801491d4
// Entry: 801491d4
// Size: 852 bytes

void FUN_801491d4(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  undefined8 uVar4;
  double dVar5;
  double dVar6;
  
  iVar3 = *(int *)(param_9 + 0x4c);
  *(undefined *)(param_10 + 0x2ef) = 0;
  if (((*(uint *)(param_10 + 0x2dc) & 0x800) != 0) && ((*(uint *)(param_10 + 0x2e0) & 0x800) == 0))
  {
    iVar1 = FUN_8002ba84();
    if (iVar1 != 0) {
      FUN_80139280(iVar1);
    }
    if ((*(uint *)(param_10 + 0x2e4) & 0x40000000) == 0) {
      if ((int)*(short *)(iVar3 + 0x18) != 0xffffffff) {
        FUN_80020000((int)*(short *)(iVar3 + 0x18));
      }
      if ((int)*(short *)(iVar3 + 0x1a) != 0xffffffff) {
        FUN_800201ac((int)*(short *)(iVar3 + 0x1a),0);
      }
    }
    *(undefined4 *)(param_10 + 0x29c) = 0;
    FUN_80035ff8(param_9);
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
    dVar5 = (double)*(float *)(param_10 + 0x318);
    if ((double)FLOAT_803e31fc == dVar5) {
      *(float *)(param_10 + 0x308) = FLOAT_803e3208;
    }
    else {
      *(float *)(param_10 + 0x308) = FLOAT_803e3200 / (float)((double)FLOAT_803e3204 * dVar5);
    }
    *(undefined *)(param_10 + 0x323) = 1;
    FUN_8003042c((double)FLOAT_803e31fc,dVar5,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,(uint)*(byte *)(param_10 + 0x321),0,param_12,param_13,param_14,param_15,
                 param_16);
    if (*(int *)(param_9 + 0x54) != 0) {
      *(undefined *)(*(int *)(param_9 + 0x54) + 0x70) = 0;
    }
    *(uint *)(param_10 + 0x2e8) = *(uint *)(param_10 + 0x2e8) | 1;
    uVar4 = FUN_8000bb38(param_9,0x233);
    uVar2 = FUN_80022264(0,100);
    if (0x32 < (int)uVar2) {
      if ((*(uint *)(param_10 + 0x2e4) & 0x100000) == 0) {
        uVar2 = (int)*(short *)(iVar3 + 0x22) & 0xf00;
        if (uVar2 != 0) {
          uVar4 = FUN_8014a14c(uVar4,dVar5,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                               param_10,uVar2,0,1,param_14,param_15,param_16);
        }
        uVar2 = (int)*(short *)(iVar3 + 0x22) & 0xf000;
        if (uVar2 != 0) {
          uVar4 = FUN_8014a14c(uVar4,dVar5,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                               param_10,uVar2,0,2,param_14,param_15,param_16);
        }
        uVar2 = (int)*(short *)(iVar3 + 0x22) & 0xff;
        if (uVar2 != 0) {
          FUN_8014a14c(uVar4,dVar5,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10,
                       uVar2,0,3,param_14,param_15,param_16);
        }
      }
      else {
        FUN_8014a14c(uVar4,dVar5,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10,
                     (uint)*(byte *)(param_10 + 0x2f5),0,4,param_14,param_15,param_16);
      }
    }
  }
  iVar1 = 0xff - (int)(FLOAT_803e3210 * *(float *)(param_9 + 0x98));
  if (iVar1 < 0) {
    iVar1 = 0;
  }
  else if (0xff < iVar1) {
    iVar1 = 0xff;
  }
  *(char *)(param_9 + 0x36) = (char)iVar1;
  dVar6 = (double)FLOAT_803e3200;
  dVar5 = (double)(float)((double)CONCAT44(0x43300000,0xff - *(byte *)(param_9 + 0x36) ^ 0x80000000)
                         - DOUBLE_803e3218);
  *(float *)(param_10 + 0x30c) = (float)(dVar6 + (double)(float)(dVar5 / (double)FLOAT_803e3210));
  if (*(byte *)(param_9 + 0x36) < 5) {
    if ((*(uint *)(param_10 + 0x2e4) & 0x40000000) != 0) {
      if ((int)*(short *)(iVar3 + 0x18) != 0xffffffff) {
        FUN_80020000((int)*(short *)(iVar3 + 0x18));
      }
      if ((int)*(short *)(iVar3 + 0x1a) != 0xffffffff) {
        dVar5 = (double)FUN_800201ac((int)*(short *)(iVar3 + 0x1a),0);
      }
    }
    *(float *)(param_10 + 0x30c) = FLOAT_803e31fc;
    *(undefined4 *)(param_10 + 0x2dc) = 0;
    *(ushort *)(param_9 + 6) = *(ushort *)(param_9 + 6) | 0x4000;
    *(undefined *)(param_9 + 0x36) = 0;
    *(undefined4 *)(param_9 + 0xf4) = 1;
    if (*(int *)(iVar3 + 0x14) == -1) {
      FUN_8002cc9c(dVar5,dVar6,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
    }
    else {
      if ((int)*(short *)(iVar3 + 0x2c) != 0) {
        (**(code **)(*DAT_803dd72c + 100))
                  ((double)(FLOAT_803e3204 *
                           (float)((double)CONCAT44(0x43300000,
                                                    (int)*(short *)(iVar3 + 0x2c) ^ 0x80000000) -
                                  DOUBLE_803e3218)));
      }
      *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) & 0xfffff7ff;
      *(uint *)(param_10 + 0x2e8) = *(uint *)(param_10 + 0x2e8) & 0xfffffffc;
    }
  }
  return;
}

