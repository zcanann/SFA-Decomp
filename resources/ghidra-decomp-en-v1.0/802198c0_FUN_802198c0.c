// Function: FUN_802198c0
// Entry: 802198c0
// Size: 448 bytes

void FUN_802198c0(undefined2 *param_1,int param_2)

{
  char cVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  iVar2 = FUN_8001ffb4((int)*(short *)(param_2 + 0x1e));
  if (iVar2 != 0) {
    *(undefined *)(iVar3 + 0x6e6) = 1;
  }
  cVar1 = *(char *)(param_2 + 0x19);
  if (cVar1 == '\x02') {
    *(undefined **)(iVar3 + 0x6dc) = &DAT_8032a7cc;
    *(code **)(iVar3 + 0x6d4) = FUN_80219224;
    *(undefined **)(iVar3 + 0x6d8) = &DAT_803dc2c8;
    FUN_80037200(param_1,3);
    if (*(char *)(iVar3 + 0x6e6) != '\0') {
      FUN_8002ce88(param_1);
      param_1[3] = param_1[3] | 0x4000;
    }
    FUN_8003393c(param_1);
    *(code **)(param_1 + 0x5e) = FUN_8021946c;
  }
  else {
    if (cVar1 < '\x02') {
      if (cVar1 != '\0') {
        if (-1 < cVar1) {
          *(undefined **)(iVar3 + 0x6dc) = &DAT_8032a7c0;
          *(code **)(iVar3 + 0x6d4) = FUN_802193dc;
          *(undefined4 *)(iVar3 + 0x6d8) = 0;
          *(code **)(param_1 + 0x5e) = FUN_8021946c;
        }
        goto LAB_80219a18;
      }
    }
    else if ('\x03' < cVar1) goto LAB_80219a18;
    FUN_800200e8(0x934,0);
    FUN_800200e8(0x933,0);
    *(undefined **)(iVar3 + 0x6dc) = &DAT_8032a7d8;
    *(code **)(iVar3 + 0x6d4) = FUN_80218fc0;
    *(undefined **)(iVar3 + 0x6d8) = &DAT_803dc2d0;
    *(code **)(param_1 + 0x5e) = FUN_80218ee8;
  }
LAB_80219a18:
  *(undefined **)(iVar3 + 0x6d0) = &DAT_8032a7e4;
  *(float *)(iVar3 + 0x6e0) = FLOAT_803e699c;
  iVar2 = FUN_800221a0(0,1);
  FUN_80030334((double)FLOAT_803e698c,param_1,(int)*(short *)(*(int *)(iVar3 + 0x6dc) + iVar2 * 2),0
              );
  param_1[0x58] = param_1[0x58] | 0x2000;
  return;
}

