// Function: FUN_802990a4
// Entry: 802990a4
// Size: 904 bytes

undefined4
FUN_802990a4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  short sVar1;
  float fVar2;
  byte bVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_9 + 0xb8);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_80035f84(param_9);
  }
  fVar2 = FLOAT_803e8b3c;
  *(float *)(param_10 + 0x294) = FLOAT_803e8b3c;
  *(float *)(param_10 + 0x284) = fVar2;
  *(float *)(param_10 + 0x280) = fVar2;
  *(float *)(param_9 + 0x24) = fVar2;
  *(float *)(param_9 + 0x28) = fVar2;
  *(float *)(param_9 + 0x2c) = fVar2;
  FUN_8011f6d0(0xe);
  FUN_8011f6ac(10);
  sVar1 = *(short *)(param_9 + 0xa0);
  if (sVar1 == 0xe1) {
    if ((FLOAT_803e8b30 < *(float *)(param_9 + 0x98)) && ((*(byte *)(param_10 + 0x356) & 1) == 0)) {
      *(byte *)(param_10 + 0x356) = *(byte *)(param_10 + 0x356) | 1;
      FUN_8000bb38(param_9,0x376);
    }
    if (*(char *)(param_10 + 0x346) == '\0') {
      return 0;
    }
    FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0xde,0,param_12,param_13,param_14,param_15,param_16);
    *(float *)(param_10 + 0x2a0) = FLOAT_803e8bd8;
    *(undefined *)(param_10 + 0x356) = 0;
    return 0;
  }
  if (sVar1 < 0xe1) {
    if (sVar1 == 0xdf) {
      if ((FLOAT_803e8b34 < *(float *)(param_9 + 0x98)) && ((*(byte *)(param_10 + 0x356) & 1) == 0))
      {
        *(byte *)(param_10 + 0x356) = *(byte *)(param_10 + 0x356) | 1;
        FUN_80014acc((double)FLOAT_803e8ba8);
        FUN_8000bb38(param_9,0x377);
        FUN_8018a13c((int)DAT_803df0b4,'\x01');
      }
      if (*(char *)(param_10 + 0x346) == '\0') {
        return 0;
      }
      FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0xe5,0,param_12,param_13,param_14,param_15,param_16);
      *(float *)(param_10 + 0x2a0) = FLOAT_803e8bd8;
      FUN_8000bb38(param_9,0x3c3);
      return 0;
    }
    if (0xde < sVar1) {
      if ((FLOAT_803e8b30 < *(float *)(param_9 + 0x98)) && ((*(byte *)(param_10 + 0x356) & 1) == 0))
      {
        *(byte *)(param_10 + 0x356) = *(byte *)(param_10 + 0x356) | 1;
        FUN_8000bb38(param_9,0x376);
      }
      if (*(char *)(param_10 + 0x346) == '\0') {
        return 0;
      }
      FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0xdf,0,param_12,param_13,param_14,param_15,param_16);
      *(float *)(param_10 + 0x2a0) = FLOAT_803e8bd8;
      *(undefined *)(param_10 + 0x356) = 0;
      return 0;
    }
    if (0xdd < sVar1) {
      if ((FLOAT_803e8b34 < *(float *)(param_9 + 0x98)) && ((*(byte *)(param_10 + 0x356) & 1) == 0))
      {
        *(byte *)(param_10 + 0x356) = *(byte *)(param_10 + 0x356) | 1;
        FUN_80014acc((double)FLOAT_803e8ba8);
        FUN_8000bb38(param_9,0x377);
        FUN_8018a13c((int)DAT_803df0b4,'\0');
      }
      if (*(char *)(param_10 + 0x346) == '\0') {
        return 0;
      }
      FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0xe4,0,param_12,param_13,param_14,param_15,param_16);
      *(float *)(param_10 + 0x2a0) = FLOAT_803e8bd8;
      FUN_8000bb38(param_9,0x3c3);
      return 0;
    }
  }
  else if ((sVar1 < 0xe6) && (0xe3 < sVar1)) {
    if (*(char *)(param_10 + 0x346) == '\0') {
      return 0;
    }
    *(uint *)(iVar4 + 0x360) = *(uint *)(iVar4 + 0x360) | 0x800000;
    *(code **)(param_10 + 0x308) = FUN_802a58ac;
    return 2;
  }
  bVar3 = FUN_8018a1b0((int)DAT_803df0b4);
  if (bVar3 == 0) {
    FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0xe0,0,param_12,param_13,param_14,param_15,param_16);
  }
  else {
    FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0xe1,0,param_12,param_13,param_14,param_15,param_16);
  }
  FUN_8018a4b4((int)DAT_803df0b4,(float *)(param_9 + 0xc),(float *)(param_9 + 0x14));
  *(float *)(param_10 + 0x2a0) = FLOAT_803e8bd8;
  *(undefined *)(param_10 + 0x356) = 0;
  *(undefined2 *)(iVar4 + 0x478) = *DAT_803df0b4;
  *(undefined2 *)(iVar4 + 0x484) = *(undefined2 *)(iVar4 + 0x478);
  if ((DAT_803df0cc != 0) && ((*(byte *)(iVar4 + 0x3f4) >> 6 & 1) != 0)) {
    *(undefined *)(iVar4 + 0x8b4) = 4;
    *(byte *)(iVar4 + 0x3f4) = *(byte *)(iVar4 + 0x3f4) & 0xf7 | 8;
  }
  return 0;
}

