// Function: FUN_800208b8
// Entry: 800208b8
// Size: 356 bytes

void FUN_800208b8(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  undefined4 uVar1;
  undefined8 uVar2;
  
  if (DAT_803dd6b9 != '\0') {
    FUN_8004a9e4();
    FUN_8004a5b8('\x01');
    FUN_8004a9e4();
    FUN_8004a5b8('\x01');
    FUN_8004a9e4();
    FUN_8004a5b8('\x01');
    FUN_800238f8(0);
    if (DAT_803dd744 != '\0') {
      uVar2 = FUN_8004a53c(0,0,0);
      uVar2 = FUN_800570f8(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      if (DAT_803dd6c0 != '\0') {
        FUN_80043938(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        DAT_803dd6c0 = '\0';
      }
    }
    uVar1 = FUN_800238f8(0);
    DAT_803dd6b9 = '\0';
    FUN_8000fc74();
    FUN_80137928();
    if (-1 < DAT_803dc07c) {
      FUN_80014974(DAT_803dc07c);
      DAT_803dc07c = -1;
    }
    FUN_800235b0();
    uVar2 = FUN_800235b0();
    if ((DAT_803dd6c1 != '\0') && (DAT_803dd778 != -1)) {
      uVar2 = FUN_80041f28();
      FUN_80043070(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,DAT_803dd778);
      if (DAT_803dd774 != -1) {
        FUN_80042f6c(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,DAT_803dd774);
      }
      uVar2 = FUN_80041f1c();
      DAT_803dd6c1 = '\0';
    }
    FUN_8005758c(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    if (DAT_803dd714 != (int *)0x0) {
      (**(code **)(*DAT_803dd714 + 0xc))(1);
    }
    FUN_800238f8(uVar1);
    DAT_803dd744 = '\x01';
  }
  return;
}

