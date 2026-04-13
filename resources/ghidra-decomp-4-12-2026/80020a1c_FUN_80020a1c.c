// Function: FUN_80020a1c
// Entry: 80020a1c
// Size: 724 bytes

void FUN_80020a1c(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,
                 undefined4 param_10,undefined4 param_11,int param_12,undefined4 param_13,
                 int param_14,undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined4 extraout_r4;
  undefined4 uVar4;
  undefined8 uVar5;
  
  FUN_8002bac4();
  DAT_803dd6c2 = 0;
  FUN_8001b738(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  if (DAT_803dd6ba == '\0') {
    (**(code **)(*DAT_803dd6d0 + 0x54))();
  }
  FUN_80014888();
  uVar5 = FUN_80102440();
  uVar4 = extraout_r4;
  FUN_80014e9c(0);
  uVar5 = FUN_8002e720(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                       (uint)DAT_803dd6bc,uVar4,param_11,param_12,param_13,param_14,param_15,
                       param_16);
  if (DAT_803dd6ba == '\0') {
    FUN_8005c968(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0);
    (**(code **)(*DAT_803dd72c + 0x70))();
    iVar3 = FUN_8002bac4();
    iVar1 = DAT_803dd754 * 0x10;
    iVar2 = DAT_803dd750 + (uint)DAT_803dc070;
    DAT_803dd750 = iVar2;
    if (iVar3 != 0) {
      *(undefined4 *)(&DAT_8033cc18 + iVar1) = *(undefined4 *)(iVar3 + 0xc);
      *(undefined4 *)(&DAT_8033cc1c + iVar1) = *(undefined4 *)(iVar3 + 0x10);
      *(undefined4 *)(&DAT_8033cc20 + iVar1) = *(undefined4 *)(iVar3 + 0x14);
      *(int *)(&DAT_8033cc24 + iVar1) = iVar2;
      DAT_803dd754 = DAT_803dd754 + 1;
      if (0x3b < DAT_803dd754) {
        DAT_803dd754 = 0;
      }
    }
  }
  FUN_8006f57c((double)FLOAT_803dc074);
  uVar5 = FUN_800147d0();
  FUN_80064e08(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar5 = FUN_80056618();
  FUN_80058210(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  FUN_8002e21c();
  (**(code **)(*DAT_803dd6ec + 0x3c))();
  FUN_80070528();
  if (DAT_803dd6c6 == 0) {
    FUN_8005c8cc();
    (**(code **)(*DAT_803dd710 + 0xc))(0);
    if (DAT_803dd6c8 == '\0') {
      FUN_80014798();
    }
    uVar5 = (**(code **)(*DAT_803dd73c + 8))();
    if (DAT_803dd6c8 == '\0') {
      FUN_80015650(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    }
    FUN_80019c5c(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  }
  else {
    DAT_803dd6c6 = DAT_803dd6c6 + -1;
    if (DAT_803dd6c6 < 0) {
      DAT_803dd6c6 = 0;
    }
  }
  if (DAT_803dd6c2 == 0) {
    if (DAT_803dd6c4 != '\0') {
      FLOAT_803dc080 = FLOAT_803dc080 - FLOAT_803dc074;
      if (FLOAT_803dc080 <= FLOAT_803df430) {
        FUN_8000a538((int *)0xc9,0);
        FUN_8000a538((int *)0xd0,0);
        DAT_803dd6c4 = '\0';
      }
    }
    if (FLOAT_803dc080 <= FLOAT_803df430) {
      FLOAT_803dc080 = FLOAT_803df434;
    }
  }
  else {
    if (DAT_803dd6c4 == '\0') {
      FLOAT_803dc080 = FLOAT_803dc080 + FLOAT_803dc074;
      if (FLOAT_803df430 <= FLOAT_803dc080) {
        FUN_8000a538((int *)(uint)DAT_803dd770,1);
        DAT_803dd6c4 = '\x01';
      }
    }
    if (FLOAT_803df430 <= FLOAT_803dc080) {
      FLOAT_803dc080 = FLOAT_803df438;
    }
  }
  FUN_8000f0d8();
  DAT_803dd6bb = DAT_803dd6bb - DAT_803dc070;
  if (DAT_803dd6bb < '\0') {
    DAT_803dd6bb = '\0';
  }
  return;
}

