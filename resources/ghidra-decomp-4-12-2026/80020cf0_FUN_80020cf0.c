// Function: FUN_80020cf0
// Entry: 80020cf0
// Size: 352 bytes

void FUN_80020cf0(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,
                 undefined4 param_10,undefined4 param_11,int param_12,undefined4 param_13,
                 int param_14,undefined4 param_15,undefined4 param_16)

{
  short sVar1;
  int iVar2;
  int *piVar3;
  undefined8 extraout_f1;
  undefined8 uVar4;
  
  FUN_8004a9e4();
  if (DAT_803dd6bd == '\x01') {
    FUN_80014f6c();
    uVar4 = FUN_80013454();
    FUN_80020a1c(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 (int)((ulonglong)uVar4 >> 0x20),(int)uVar4,param_11,param_12,param_13,param_14,
                 param_15,param_16);
    FUN_8000e3a0();
    uVar4 = FUN_8001f740();
    FUN_80048350(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    FUN_80009bd0();
    FUN_8000d754();
  }
  FUN_80137950();
  uVar4 = (**(code **)(*DAT_803dd6cc + 4))(0,0,0);
  if (DAT_803dd6bd == '\x01') {
    if (DAT_803dd6c8 != 0) {
      if (DAT_803dd6c6 == 0) {
        param_2 = (double)FLOAT_803df430;
        FUN_8007668c(param_2,param_2,0x280,0x1e0);
        piVar3 = (int *)&DAT_803dd768;
        for (iVar2 = 0; iVar2 < (int)(uint)DAT_803dd6c8; iVar2 = iVar2 + 1) {
          FUN_8003b9ec(*piVar3);
          sVar1 = *(short *)(*piVar3 + 0x46);
          if ((sVar1 == 0x882) || (sVar1 == 0x887)) {
            FUN_800415ac(*piVar3);
          }
          piVar3 = piVar3 + 1;
        }
        uVar4 = FUN_80014798();
      }
      FUN_80015650(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      uVar4 = FUN_80019c5c(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    }
    FUN_8001b520(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    FUN_80014f68();
    uVar4 = FUN_8001b4f8(0);
  }
  FUN_8004a5b8('\x01');
  FUN_8002e4f4(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar4 = FUN_800235b0();
  FUN_800208b8(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  return;
}

