// Function: FUN_802a52d8
// Entry: 802a52d8
// Size: 444 bytes

undefined4
FUN_802a52d8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  short sVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_9 + 0xb8);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0x447,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined2 *)(param_10 + 0x278) = 1;
    *(code **)(iVar4 + 0x898) = FUN_802a58ac;
  }
  if (((*(uint *)(param_10 + 0x314) & 1) == 0) || (*(int *)(iVar4 + 0x7f8) == 0)) goto LAB_802a53b4;
  sVar1 = *(short *)(*(int *)(iVar4 + 0x7f8) + 0x46);
  if (sVar1 == 0x519) {
LAB_802a5398:
    FUN_8000bb38(param_9,0x39b);
    goto LAB_802a53b4;
  }
  if (sVar1 < 0x519) {
    if (sVar1 < 500) {
      if (sVar1 == 0x6d) goto LAB_802a5388;
    }
    else if (sVar1 < 0x1fa) goto LAB_802a5398;
  }
  else if (sVar1 == 0x754) {
LAB_802a5388:
    FUN_8000bb38(param_9,799);
    goto LAB_802a53b4;
  }
  FUN_8000bb38(param_9,0x6d);
LAB_802a53b4:
  *(float *)(param_10 + 0x280) = FLOAT_803e8b3c;
  *(float *)(param_10 + 0x2a0) = FLOAT_803e8bd8;
  if ((*(int *)(iVar4 + 0x7f8) == 0) && (*(char *)(param_10 + 0x346) != '\0')) {
    *(uint *)(iVar4 + 0x360) = *(uint *)(iVar4 + 0x360) | 0x800000;
    *(code **)(param_10 + 0x308) = FUN_802a58ac;
    uVar2 = 2;
  }
  else {
    if ((*(int *)(iVar4 + 0x7f8) != 0) && (FLOAT_803e8be0 < *(float *)(param_9 + 0x98))) {
      *(undefined *)(iVar4 + 0x800) = 0;
      iVar3 = *(int *)(iVar4 + 0x7f8);
      if (iVar3 != 0) {
        if ((*(short *)(iVar3 + 0x46) == 0x3cf) || (*(short *)(iVar3 + 0x46) == 0x662)) {
          FUN_80182a5c(iVar3);
        }
        else {
          FUN_800ea9f8(iVar3);
        }
        *(ushort *)(*(int *)(iVar4 + 0x7f8) + 6) = *(ushort *)(*(int *)(iVar4 + 0x7f8) + 6) & 0xbfff
        ;
        *(undefined4 *)(*(int *)(iVar4 + 0x7f8) + 0xf8) = 0;
        *(undefined4 *)(iVar4 + 0x7f8) = 0;
      }
    }
    uVar2 = 0;
  }
  return uVar2;
}

