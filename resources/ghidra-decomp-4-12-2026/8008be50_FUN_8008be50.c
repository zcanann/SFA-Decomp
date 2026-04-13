// Function: FUN_8008be50
// Entry: 8008be50
// Size: 484 bytes

void FUN_8008be50(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  bool bVar1;
  int iVar2;
  undefined4 extraout_r4;
  undefined8 uVar3;
  
  bVar1 = false;
  while (iVar2 = FUN_800431a4(), iVar2 != 0) {
    uVar3 = FUN_80014f6c();
    FUN_80020390();
    if (bVar1) {
      uVar3 = FUN_8004a9e4();
    }
    param_1 = FUN_80048350(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    FUN_80015650(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    if (bVar1) {
      uVar3 = FUN_800235b0();
      param_1 = FUN_80019c5c(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      FUN_8004a5b8('\x01');
    }
    if (DAT_803dd5d0 != '\0') {
      bVar1 = true;
    }
  }
  DAT_803ddde4 = 0;
  DAT_803ddddc = 0;
  DAT_803dddd8 = 0xff;
  uRam803dddd9 = 0xff;
  uRam803dddda = 0xff;
  if (DAT_803dddc4 == (int *)0x0) {
    DAT_803dddc4 = FUN_8001f58c(0,'\x01');
    if (DAT_803dddc4 != (int *)0x0) {
      FUN_8001dbf0((int)DAT_803dddc4,4);
      param_3 = (double)FLOAT_803dfcd8;
      param_2 = (double)FLOAT_803dfcec;
      FUN_8001dd54(param_3,param_2,param_3,DAT_803dddc4);
      FUN_8001dbb4((int)DAT_803dddc4,0xff,0xff,0xff,0xff);
      param_11 = 0xff;
      param_12 = 0xff;
      param_13 = 0xff;
      param_1 = FUN_8001dadc((int)DAT_803dddc4,0xff,0xff,0xff,0xff);
    }
    DAT_803ddde8 = FUN_8001f58c(0,'\x01');
    if (DAT_803ddde8 != (int *)0x0) {
      FUN_8001dbf0((int)DAT_803ddde8,4);
      param_3 = (double)FLOAT_803dfcd8;
      param_2 = (double)FLOAT_803dfcdc;
      FUN_8001dd54(param_3,param_2,param_3,DAT_803ddde8);
      FUN_8001dbb4((int)DAT_803ddde8,0xff,0xff,0xff,0xff);
      param_11 = 0xff;
      param_12 = 0xff;
      param_13 = 0xff;
      param_1 = FUN_8001dadc((int)DAT_803ddde8,0xff,0xff,0xff,0xff);
    }
  }
  FUN_8008c034(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  FUN_80088f20(7,'\0');
  FUN_800890e0((double)FLOAT_803dfcd8,0);
  FUN_8008a78c();
  FUN_8008a2d8();
  DAT_8030fe88 = FLOAT_803dfcd8;
  DAT_8030fe8c = FLOAT_803dfcec;
  DAT_8030fe90 = FLOAT_803dfcd8;
  DAT_8030fe94 = FLOAT_803dfcd8;
  DAT_8030fe98 = FLOAT_803dfcec;
  DAT_8030fe9c = FLOAT_803dfcd8;
  DAT_803dddd0 = FUN_80054ed0((double)FLOAT_803dfcd8,param_2,param_3,param_4,param_5,param_6,param_7
                              ,param_8,0x5fa,extraout_r4,param_11,param_12,param_13,param_14,
                              param_15,param_16);
  return;
}

