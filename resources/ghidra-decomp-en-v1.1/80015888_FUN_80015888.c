// Function: FUN_80015888
// Entry: 80015888
// Size: 260 bytes

void FUN_80015888(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,uint param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  bool bVar1;
  undefined8 extraout_f1;
  undefined8 uVar2;
  undefined8 uVar3;
  
  uVar3 = FUN_8028683c();
  bVar1 = false;
  DAT_803dd5d8 = 0;
  uVar2 = extraout_f1;
  while (((DAT_803dd5d8 == 0 || (DAT_803dd5d8 == -1)) || (DAT_803dd5d8 == -3))) {
    FUN_80249610(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 (undefined4 *)((ulonglong)uVar3 >> 0x20),(int)uVar3,param_11,param_12,&LAB_8001598c
                 ,2,param_15,param_16);
    while ((DAT_803dd5d8 == 0 || (DAT_803dd5d8 == -1))) {
      uVar2 = FUN_80014f6c();
      FUN_80020390();
      if (bVar1) {
        uVar2 = FUN_8004a9e4();
      }
      FUN_80015650(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      if (bVar1) {
        uVar2 = FUN_800235b0();
        uVar2 = FUN_80019c5c(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        FUN_8004a5b8('\x01');
      }
      if (DAT_803dd5d0 != '\0') {
        bVar1 = true;
      }
    }
  }
  FUN_80286888();
  return;
}

