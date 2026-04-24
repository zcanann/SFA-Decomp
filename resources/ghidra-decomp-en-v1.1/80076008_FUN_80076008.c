// Function: FUN_80076008
// Entry: 80076008
// Size: 316 bytes

void FUN_80076008(undefined8 param_1,double param_2,double param_3,double param_4,undefined4 param_5
                 ,undefined4 param_6,undefined2 param_7,undefined2 param_8)

{
  undefined2 uVar1;
  undefined2 extraout_r4;
  double extraout_f1;
  double dVar2;
  
  uVar1 = FUN_802867ac();
  dVar2 = extraout_f1;
  FUN_80257b5c();
  FUN_802570dc(0,1);
  FUN_802570dc(9,1);
  FUN_802570dc(0xd,1);
  FUN_80259288(0);
  FUN_8025d6ac((undefined4 *)&DAT_803974e0,1);
  FUN_80259000(0x80,1,4);
  DAT_cc008000._0_1_ = 0x3c;
  DAT_cc008000._0_2_ = uVar1;
  DAT_cc008000._0_2_ = extraout_r4;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000 = (float)dVar2;
  DAT_cc008000 = (float)param_2;
  DAT_cc008000._0_1_ = 0x3c;
  DAT_cc008000._0_2_ = param_7;
  DAT_cc008000._0_2_ = extraout_r4;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000 = (float)param_3;
  DAT_cc008000 = (float)param_2;
  DAT_cc008000._0_1_ = 0x3c;
  DAT_cc008000._0_2_ = param_7;
  DAT_cc008000._0_2_ = param_8;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000 = (float)param_3;
  DAT_cc008000 = (float)param_4;
  DAT_cc008000._0_1_ = 0x3c;
  DAT_cc008000._0_2_ = uVar1;
  DAT_cc008000._0_2_ = param_8;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000 = (float)dVar2;
  DAT_cc008000 = (float)param_4;
  FUN_8000fb20();
  FUN_802867f8();
  return;
}

