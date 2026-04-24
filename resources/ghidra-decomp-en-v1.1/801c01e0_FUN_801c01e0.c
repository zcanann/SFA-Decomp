// Function: FUN_801c01e0
// Entry: 801c01e0
// Size: 648 bytes

void FUN_801c01e0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)

{
  double dVar1;
  float fVar2;
  short sVar3;
  uint uVar4;
  int iVar5;
  short *psVar6;
  
  psVar6 = *(short **)(param_9 + 0x5c);
  if (*psVar6 == 0) {
    *(uint *)(param_9 + 0x7a) = *(int *)(param_9 + 0x7a) - (uint)DAT_803dc070;
    if (*(int *)(param_9 + 0x7a) < 0) {
      FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
      return;
    }
    FUN_80035eec((int)param_9,5,4,0);
    FUN_80035a6c((int)param_9,10);
    *(float *)(param_9 + 0x14) = -(FLOAT_803e59f8 * FLOAT_803dc074 - *(float *)(param_9 + 0x14));
    *(float *)(param_9 + 0x14) = *(float *)(param_9 + 0x14) * FLOAT_803e59fc;
    dVar1 = DOUBLE_803e59f0;
    *param_9 = (short)(int)(FLOAT_803e5a00 * FLOAT_803dc074 +
                           (float)((double)CONCAT44(0x43300000,(int)*param_9 ^ 0x80000000) -
                                  DOUBLE_803e59f0));
    fVar2 = FLOAT_803e5a04;
    param_9[2] = (short)(int)(FLOAT_803e5a04 * FLOAT_803dc074 +
                             (float)((double)CONCAT44(0x43300000,(int)param_9[2] ^ 0x80000000) -
                                    dVar1));
    param_9[1] = (short)(int)(fVar2 * FLOAT_803dc074 +
                             (float)((double)CONCAT44(0x43300000,(int)param_9[1] ^ 0x80000000) -
                                    dVar1));
    FUN_8002ba34((double)(*(float *)(param_9 + 0x12) * FLOAT_803dc074),
                 (double)(*(float *)(param_9 + 0x14) * FLOAT_803dc074),
                 (double)(*(float *)(param_9 + 0x16) * FLOAT_803dc074),(int)param_9);
    iVar5 = 0;
    do {
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x4ba,0,1,0xffffffff,0);
      iVar5 = iVar5 + 1;
    } while (iVar5 < 3);
    if (*(char *)(*(int *)(param_9 + 0x2a) + 0xad) != '\0') {
      *(undefined4 *)(param_9 + 6) = *(undefined4 *)(*(int *)(param_9 + 0x2a) + 0x3c);
      *(float *)(param_9 + 8) = *(float *)(*(int *)(param_9 + 0x2a) + 0x40) - FLOAT_803e59e8;
      *(undefined4 *)(param_9 + 10) = *(undefined4 *)(*(int *)(param_9 + 0x2a) + 0x44);
      *psVar6 = 1;
    }
  }
  else {
    FUN_801bfe8c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  }
  iVar5 = *(int *)(psVar6 + 2);
  if (((iVar5 != 0) && (*(char *)(iVar5 + 0x2f8) != '\0')) && (*(char *)(iVar5 + 0x4c) != '\0')) {
    sVar3 = (ushort)*(byte *)(iVar5 + 0x2f9) + (short)*(char *)(iVar5 + 0x2fa);
    if (sVar3 < 0) {
      sVar3 = 0;
      *(undefined *)(iVar5 + 0x2fa) = 0;
    }
    else if (0xc < sVar3) {
      uVar4 = FUN_80022264(0xfffffff4,0xc);
      sVar3 = sVar3 + (short)uVar4;
      if (0xff < sVar3) {
        sVar3 = 0xff;
        *(undefined *)(*(int *)(psVar6 + 2) + 0x2fa) = 0;
      }
    }
    *(char *)(*(int *)(psVar6 + 2) + 0x2f9) = (char)sVar3;
  }
  return;
}

