// Function: FUN_80075534
// Entry: 80075534
// Size: 716 bytes

void FUN_80075534(undefined4 param_1,undefined4 param_2,int param_3,int param_4,undefined4 *param_5)

{
  undefined2 uVar1;
  undefined2 uVar2;
  undefined2 uVar3;
  undefined8 uVar4;
  undefined4 local_28 [10];
  
  uVar4 = FUN_80286840();
  FUN_80257b5c();
  FUN_802570dc(0,1);
  FUN_802570dc(9,1);
  FUN_802570dc(0xd,1);
  FUN_80259288(0);
  FUN_8025d6ac((undefined4 *)&DAT_803974e0,1);
  if ((((DAT_803ddc98 != '\0') || (DAT_803ddc94 != 7)) || (DAT_803ddc92 != '\0')) ||
     (DAT_803ddc9a == '\0')) {
    FUN_8025ce6c(0,7,0);
    DAT_803ddc98 = '\0';
    DAT_803ddc94 = 7;
    DAT_803ddc92 = '\0';
    DAT_803ddc9a = '\x01';
  }
  FUN_8025cce8(1,4,5,5);
  *(char *)((int)param_5 + 3) = (char)((uint)*(byte *)((int)param_5 + 3) * (uint)DAT_803dc2d9 >> 8);
  local_28[0] = *param_5;
  FUN_8025c510(0,(byte *)local_28);
  FUN_8025c5f0(0,0x1c);
  FUN_8025c584(0,0xc);
  FUN_8025c828(0,0xff,0xff,4);
  FUN_8025be80(0);
  FUN_8025c1a4(0,0xf,0xf,0xf,0xe);
  FUN_8025c224(0,7,7,7,6);
  FUN_8025c65c(0,0,0);
  FUN_8025c2a8(0,0,0,0,1,0);
  FUN_8025c368(0,0,0,0,1,0);
  FUN_8025a608(0,0,0,1,0,0,2);
  FUN_8025a608(2,0,0,1,0,0,2);
  FUN_8025a5bc(1);
  FUN_8025be54(0);
  FUN_80258944(0);
  FUN_8025ca04(1);
  FUN_80259000(0x80,1,4);
  DAT_cc008000._0_1_ = 0x3c;
  uVar1 = (undefined2)((int)((ulonglong)uVar4 >> 0x20) << 2);
  DAT_cc008000._0_2_ = uVar1;
  uVar2 = (undefined2)((int)uVar4 << 2);
  DAT_cc008000._0_2_ = uVar2;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000 = FLOAT_803dfb5c;
  DAT_cc008000 = FLOAT_803dfb5c;
  DAT_cc008000._0_1_ = 0x3c;
  uVar3 = (undefined2)(param_3 << 2);
  DAT_cc008000._0_2_ = uVar3;
  DAT_cc008000._0_2_ = uVar2;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000 = FLOAT_803dfb5c;
  DAT_cc008000 = FLOAT_803dfb5c;
  DAT_cc008000._0_1_ = 0x3c;
  DAT_cc008000._0_2_ = uVar3;
  uVar2 = (undefined2)(param_4 << 2);
  DAT_cc008000._0_2_ = uVar2;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000 = FLOAT_803dfb5c;
  DAT_cc008000 = FLOAT_803dfb5c;
  DAT_cc008000._0_1_ = 0x3c;
  DAT_cc008000._0_2_ = uVar1;
  DAT_cc008000._0_2_ = uVar2;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000 = FLOAT_803dfb5c;
  DAT_cc008000 = FLOAT_803dfb5c;
  FUN_8000fb20();
  FUN_8028688c();
  return;
}

