// Function: FUN_8029ad44
// Entry: 8029ad44
// Size: 392 bytes

int FUN_8029ad44(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                short *param_9,int param_10,undefined4 param_11,float *param_12,undefined4 *param_13
                ,undefined4 param_14,undefined4 param_15,int param_16)

{
  short sVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_9 + 0x5c);
  iVar2 = FUN_802acf3c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                       param_10,iVar4,param_12,param_13,param_14,param_15,param_16);
  if (iVar2 == 0) {
    FUN_8011f6d0(6);
    FUN_8011f6ac(10);
    if (*(char *)(param_10 + 0x27a) != '\0') {
      iVar2 = *(int *)(*(int *)(param_9 + 0x5c) + 0x35c);
      sVar1 = *(short *)(iVar2 + 4);
      if (sVar1 < 0) {
        sVar1 = 0;
      }
      else if (*(short *)(iVar2 + 6) < sVar1) {
        sVar1 = *(short *)(iVar2 + 6);
      }
      *(short *)(iVar2 + 4) = sVar1;
      FLOAT_803df0dc = FLOAT_803e8bc8;
    }
    if (((FLOAT_803e8bc8 == FLOAT_803df0dc) || (FLOAT_803e8c38 == FLOAT_803df0dc)) ||
       (FLOAT_803e8c3c == FLOAT_803df0dc)) {
      uVar3 = FUN_80022264(0xffffff38,200);
      FUN_802aaa10((double)*(float *)(iVar4 + 0x7bc),
                   (double)((float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) -
                                   DOUBLE_803e8b58) / FLOAT_803e8bf4),param_3,param_4,param_5,
                   param_6,param_7,param_8);
    }
    FLOAT_803df0dc = FLOAT_803df0dc - FLOAT_803e8b78;
    if (FLOAT_803e8b3c <= FLOAT_803df0dc) {
      if ((*(int *)(param_10 + 0x2d0) == 0) &&
         (((*(ushort *)(iVar4 + 0x6e2) & 0x200) != 0 || (*(char *)(iVar4 + 0x8c8) != 'R')))) {
        *(code **)(param_10 + 0x308) = FUN_8029ab80;
        iVar2 = 0x2c;
      }
      else {
        iVar2 = 0;
      }
    }
    else {
      *(code **)(param_10 + 0x308) = FUN_8029ac08;
      iVar2 = 0x2d;
    }
  }
  return iVar2;
}

