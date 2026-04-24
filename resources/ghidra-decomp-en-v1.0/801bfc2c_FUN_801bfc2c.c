// Function: FUN_801bfc2c
// Entry: 801bfc2c
// Size: 648 bytes

void FUN_801bfc2c(short *param_1)

{
  double dVar1;
  float fVar2;
  short sVar3;
  short sVar4;
  int iVar5;
  short *psVar6;
  
  psVar6 = *(short **)(param_1 + 0x5c);
  if (*psVar6 == 0) {
    *(uint *)(param_1 + 0x7a) = *(int *)(param_1 + 0x7a) - (uint)DAT_803db410;
    if (*(int *)(param_1 + 0x7a) < 0) {
      FUN_8002cbc4();
      return;
    }
    FUN_80035df4(param_1,5,4,0);
    FUN_80035974(param_1,10);
    *(float *)(param_1 + 0x14) = -(FLOAT_803e4d60 * FLOAT_803db414 - *(float *)(param_1 + 0x14));
    *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) * FLOAT_803e4d64;
    dVar1 = DOUBLE_803e4d58;
    *param_1 = (short)(int)(FLOAT_803e4d68 * FLOAT_803db414 +
                           (float)((double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000) -
                                  DOUBLE_803e4d58));
    fVar2 = FLOAT_803e4d6c;
    param_1[2] = (short)(int)(FLOAT_803e4d6c * FLOAT_803db414 +
                             (float)((double)CONCAT44(0x43300000,(int)param_1[2] ^ 0x80000000) -
                                    dVar1));
    param_1[1] = (short)(int)(fVar2 * FLOAT_803db414 +
                             (float)((double)CONCAT44(0x43300000,(int)param_1[1] ^ 0x80000000) -
                                    dVar1));
    FUN_8002b95c((double)(*(float *)(param_1 + 0x12) * FLOAT_803db414),
                 (double)(*(float *)(param_1 + 0x14) * FLOAT_803db414),
                 (double)(*(float *)(param_1 + 0x16) * FLOAT_803db414),param_1);
    iVar5 = 0;
    do {
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x4ba,0,1,0xffffffff,0);
      iVar5 = iVar5 + 1;
    } while (iVar5 < 3);
    if (*(char *)(*(int *)(param_1 + 0x2a) + 0xad) != '\0') {
      *(undefined4 *)(param_1 + 6) = *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x3c);
      *(float *)(param_1 + 8) = *(float *)(*(int *)(param_1 + 0x2a) + 0x40) - FLOAT_803e4d50;
      *(undefined4 *)(param_1 + 10) = *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x44);
      *psVar6 = 1;
    }
  }
  else {
    FUN_801bf8d8();
  }
  iVar5 = *(int *)(psVar6 + 2);
  if (((iVar5 != 0) && (*(char *)(iVar5 + 0x2f8) != '\0')) && (*(char *)(iVar5 + 0x4c) != '\0')) {
    sVar3 = (ushort)*(byte *)(iVar5 + 0x2f9) + (short)*(char *)(iVar5 + 0x2fa);
    if (sVar3 < 0) {
      sVar3 = 0;
      *(undefined *)(iVar5 + 0x2fa) = 0;
    }
    else if (0xc < sVar3) {
      sVar4 = FUN_800221a0(0xfffffff4,0xc);
      sVar3 = sVar3 + sVar4;
      if (0xff < sVar3) {
        sVar3 = 0xff;
        *(undefined *)(*(int *)(psVar6 + 2) + 0x2fa) = 0;
      }
    }
    *(char *)(*(int *)(psVar6 + 2) + 0x2f9) = (char)sVar3;
  }
  return;
}

