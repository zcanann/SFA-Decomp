// Function: FUN_80075e8c
// Entry: 80075e8c
// Size: 316 bytes

void FUN_80075e8c(undefined8 param_1,double param_2,double param_3,double param_4,undefined4 param_5
                 ,undefined4 param_6,undefined2 param_7,undefined2 param_8)

{
  undefined2 uVar1;
  undefined2 extraout_r4;
  double extraout_f1;
  double dVar2;
  
  uVar1 = FUN_80286048();
  dVar2 = extraout_f1;
  FUN_802573f8();
  FUN_80256978(0,1);
  FUN_80256978(9,1);
  FUN_80256978(0xd,1);
  FUN_80258b24(0);
  FUN_8025cf48(&DAT_80396880,1);
  FUN_8025889c(0x80,1,4);
  write_volatile_1(DAT_cc008000,0x3c);
  write_volatile_2(0xcc008000,uVar1);
  write_volatile_2(0xcc008000,extraout_r4);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_4(0xcc008000,(float)dVar2);
  write_volatile_4(0xcc008000,(float)param_2);
  write_volatile_1(DAT_cc008000,0x3c);
  write_volatile_2(0xcc008000,param_7);
  write_volatile_2(0xcc008000,extraout_r4);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_4(0xcc008000,(float)param_3);
  write_volatile_4(0xcc008000,(float)param_2);
  write_volatile_1(DAT_cc008000,0x3c);
  write_volatile_2(0xcc008000,param_7);
  write_volatile_2(0xcc008000,param_8);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_4(0xcc008000,(float)param_3);
  write_volatile_4(0xcc008000,(float)param_4);
  write_volatile_1(DAT_cc008000,0x3c);
  write_volatile_2(0xcc008000,uVar1);
  write_volatile_2(0xcc008000,param_8);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_4(0xcc008000,(float)dVar2);
  write_volatile_4(0xcc008000,(float)param_4);
  FUN_8000fb00();
  FUN_80286094();
  return;
}

