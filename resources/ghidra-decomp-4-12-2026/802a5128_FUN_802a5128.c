// Function: FUN_802a5128
// Entry: 802a5128
// Size: 388 bytes

undefined4
FUN_802a5128(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  ushort uVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  
  iVar5 = *(int *)(param_9 + 0xb8);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    if (*(int *)(iVar5 + 0x7f8) != 0) {
      FUN_80035f84(*(int *)(iVar5 + 0x7f8));
    }
    FUN_8003042c((double)FLOAT_803e8b44,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0x443,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined2 *)(param_10 + 0x278) = 1;
    *(code **)(iVar5 + 0x898) = FUN_802a58ac;
  }
  fVar1 = FLOAT_803e8b3c;
  *(float *)(param_10 + 0x294) = FLOAT_803e8b3c;
  *(float *)(param_10 + 0x284) = fVar1;
  *(float *)(param_10 + 0x280) = fVar1;
  *(float *)(param_9 + 0x24) = fVar1;
  *(float *)(param_9 + 0x28) = fVar1;
  *(float *)(param_9 + 0x2c) = fVar1;
  *(float *)(param_10 + 0x2a0) = FLOAT_803e8cf0;
  if ((*(uint *)(param_10 + 0x314) & 1) != 0) {
    if (*(short *)(iVar5 + 0x81a) == 0) {
      uVar2 = 0x327;
    }
    else {
      uVar2 = 0x379;
    }
    FUN_8000bb38(param_9,uVar2);
  }
  if ((*(int *)(iVar5 + 0x7f8) == 0) && (*(char *)(param_10 + 0x346) != '\0')) {
    *(code **)(param_10 + 0x308) = FUN_802a58ac;
    uVar3 = 2;
  }
  else {
    if ((*(int *)(iVar5 + 0x7f8) != 0) && (FLOAT_803e8b34 < *(float *)(param_9 + 0x98))) {
      *(undefined *)(iVar5 + 0x800) = 0;
      iVar4 = *(int *)(iVar5 + 0x7f8);
      if (iVar4 != 0) {
        if ((*(short *)(iVar4 + 0x46) == 0x3cf) || (*(short *)(iVar4 + 0x46) == 0x662)) {
          FUN_80182a5c(iVar4);
        }
        else {
          FUN_800ea9f8(iVar4);
        }
        *(ushort *)(*(int *)(iVar5 + 0x7f8) + 6) = *(ushort *)(*(int *)(iVar5 + 0x7f8) + 6) & 0xbfff
        ;
        *(undefined4 *)(*(int *)(iVar5 + 0x7f8) + 0xf8) = 0;
        *(undefined4 *)(iVar5 + 0x7f8) = 0;
      }
    }
    uVar3 = 0;
  }
  return uVar3;
}

