// Function: FUN_8029bf10
// Entry: 8029bf10
// Size: 484 bytes

int FUN_8029bf10(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                short *param_9,int param_10,undefined4 param_11,float *param_12,undefined4 *param_13
                ,undefined4 param_14,undefined4 param_15,int param_16)

{
  short sVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_9 + 0x5c);
  iVar3 = FUN_802acf3c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                       param_10,iVar4,param_12,param_13,param_14,param_15,param_16);
  fVar2 = FLOAT_803e8b3c;
  if (iVar3 == 0) {
    *(float *)(param_10 + 0x294) = FLOAT_803e8b3c;
    *(float *)(param_10 + 0x284) = fVar2;
    *(float *)(param_10 + 0x280) = fVar2;
    *(float *)(param_9 + 0x12) = fVar2;
    *(float *)(param_9 + 0x14) = fVar2;
    *(float *)(param_9 + 0x16) = fVar2;
    FUN_8011f6d0(6);
    FUN_8011f6ac(10);
    sVar1 = param_9[0x50];
    if (sVar1 == 0x448) {
      if ((((FLOAT_803e8b34 < *(float *)(param_9 + 0x4c)) && (*(char *)(iVar4 + 0x8b3) == '\0')) &&
          (FUN_8000bb38((uint)param_9,0x2c), DAT_803df0cc != 0)) &&
         ((*(byte *)(iVar4 + 0x3f4) >> 6 & 1) != 0)) {
        *(undefined *)(iVar4 + 0x8b4) = 2;
        *(byte *)(iVar4 + 0x3f4) = *(byte *)(iVar4 + 0x3f4) & 0xf7;
      }
      if (*(char *)(param_10 + 0x346) != '\0') {
        *(code **)(param_10 + 0x308) = FUN_8029ac08;
        return 0x2d;
      }
    }
    else if ((sVar1 < 0x448) && (sVar1 == 0x43d)) {
      if (*(char *)(param_10 + 0x346) != '\0') {
        *(code **)(param_10 + 0x308) = FUN_8029ac08;
        return 0x2d;
      }
    }
    else {
      FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0x43d,0,param_12,param_13,param_14,param_15,param_16);
      *(float *)(param_10 + 0x2a0) = FLOAT_803e8be4;
      if ((DAT_803df0cc != 0) && ((*(byte *)(iVar4 + 0x3f4) >> 6 & 1) != 0)) {
        *(undefined *)(iVar4 + 0x8b4) = 4;
        *(byte *)(iVar4 + 0x3f4) = *(byte *)(iVar4 + 0x3f4) & 0xf7 | 8;
      }
      fVar2 = FLOAT_803e8b3c;
      FLOAT_803df0e0 = FLOAT_803e8b3c;
      FLOAT_803df0e4 = FLOAT_803e8b3c;
      *(float *)(iVar4 + 0x7bc) = FLOAT_803e8b3c;
      *(float *)(iVar4 + 0x7b8) = fVar2;
    }
    if (((*(ushort *)(iVar4 + 0x6e2) & 0x200) == 0) && (*(char *)(iVar4 + 0x8c8) == 'R')) {
      iVar3 = 0;
    }
    else {
      FUN_80014b68(0,0x200);
      *(code **)(param_10 + 0x308) = FUN_8029ab80;
      iVar3 = 0x2c;
    }
  }
  return iVar3;
}

