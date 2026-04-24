// Function: FUN_800753b8
// Entry: 800753b8
// Size: 716 bytes

void FUN_800753b8(undefined4 param_1,undefined4 param_2,int param_3,int param_4,undefined4 *param_5)

{
  undefined2 uVar1;
  undefined2 uVar2;
  undefined2 uVar3;
  undefined8 uVar4;
  undefined4 local_28 [10];
  
  uVar4 = FUN_802860dc();
  FUN_802573f8();
  FUN_80256978(0,1);
  FUN_80256978(9,1);
  FUN_80256978(0xd,1);
  FUN_80258b24(0);
  FUN_8025cf48(&DAT_80396880,1);
  if ((((DAT_803dd018 != '\0') || (DAT_803dd014 != 7)) || (DAT_803dd012 != '\0')) ||
     (DAT_803dd01a == '\0')) {
    FUN_8025c708(0,7,0);
    DAT_803dd018 = '\0';
    DAT_803dd014 = 7;
    DAT_803dd012 = '\0';
    DAT_803dd01a = '\x01';
  }
  FUN_8025c584(1,4,5,5);
  *(char *)((int)param_5 + 3) = (char)((uint)*(byte *)((int)param_5 + 3) * (uint)DAT_803db679 >> 8);
  local_28[0] = *param_5;
  FUN_8025bdac(0,local_28);
  FUN_8025be8c(0,0x1c);
  FUN_8025be20(0,0xc);
  FUN_8025c0c4(0,0xff,0xff,4);
  FUN_8025b71c(0);
  FUN_8025ba40(0,0xf,0xf,0xf,0xe);
  FUN_8025bac0(0,7,7,7,6);
  FUN_8025bef8(0,0,0);
  FUN_8025bb44(0,0,0,0,1,0);
  FUN_8025bc04(0,0,0,0,1,0);
  FUN_80259ea4(0,0,0,1,0,0,2);
  FUN_80259ea4(2,0,0,1,0,0,2);
  FUN_80259e58(1);
  FUN_8025b6f0(0);
  FUN_802581e0(0);
  FUN_8025c2a0(1);
  FUN_8025889c(0x80,1,4);
  write_volatile_1(DAT_cc008000,0x3c);
  uVar1 = (undefined2)((int)((ulonglong)uVar4 >> 0x20) << 2);
  write_volatile_2(0xcc008000,uVar1);
  uVar2 = (undefined2)((int)uVar4 << 2);
  write_volatile_2(0xcc008000,uVar2);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_4(0xcc008000,FLOAT_803deedc);
  write_volatile_4(0xcc008000,FLOAT_803deedc);
  write_volatile_1(DAT_cc008000,0x3c);
  uVar3 = (undefined2)(param_3 << 2);
  write_volatile_2(0xcc008000,uVar3);
  write_volatile_2(0xcc008000,uVar2);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_4(0xcc008000,FLOAT_803deedc);
  write_volatile_4(0xcc008000,FLOAT_803deedc);
  write_volatile_1(DAT_cc008000,0x3c);
  write_volatile_2(0xcc008000,uVar3);
  uVar2 = (undefined2)(param_4 << 2);
  write_volatile_2(0xcc008000,uVar2);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_4(0xcc008000,FLOAT_803deedc);
  write_volatile_4(0xcc008000,FLOAT_803deedc);
  write_volatile_1(DAT_cc008000,0x3c);
  write_volatile_2(0xcc008000,uVar1);
  write_volatile_2(0xcc008000,uVar2);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_4(0xcc008000,FLOAT_803deedc);
  write_volatile_4(0xcc008000,FLOAT_803deedc);
  FUN_8000fb00();
  FUN_80286128();
  return;
}

