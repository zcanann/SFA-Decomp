// Function: FUN_80076d78
// Entry: 80076d78
// Size: 1060 bytes

void FUN_80076d78(undefined4 param_1,undefined4 param_2,int param_3,undefined4 *param_4,uint param_5
                 ,uint param_6)

{
  short sVar1;
  uint uVar2;
  uint uVar3;
  short sVar4;
  short sVar5;
  int iVar6;
  undefined8 uVar7;
  undefined4 local_28 [10];
  
  uVar7 = FUN_802860d8();
  iVar6 = (int)((ulonglong)uVar7 >> 0x20);
  FUN_802573f8();
  FUN_80256978(0,1);
  FUN_80256978(9,1);
  FUN_80256978(0xd,1);
  *(char *)((int)param_4 + 3) = (char)((uint)*(byte *)((int)param_4 + 3) * (uint)DAT_803db679 >> 8);
  local_28[0] = *param_4;
  FUN_8025bdac(0,local_28);
  FUN_8025be20(0,0xc);
  FUN_8025be8c(0,0x1c);
  FUN_8025c0c4(0,0,0,0xff);
  FUN_8025b71c(0);
  if ((param_6 & 0xff) == 0) {
    FUN_8025ba40(0,0xf,0xe,8,0xf);
  }
  else {
    FUN_8025ba40(0,0xf,0xf,0xf,0xe);
  }
  FUN_8025bac0(0,7,4,6,7);
  FUN_8025bef8(0,0,0);
  FUN_8025bb44(0,0,0,0,1,0);
  FUN_8025bc04(0,0,0,2,1,0);
  if (*(int *)(iVar6 + 0x50) == 0) {
    FUN_8025c2a0(1);
  }
  else {
    FUN_8025be8c(1,0x1c);
    FUN_8025c0c4(0,0,1,0xff);
    FUN_8025ba40(1,0xf,0xf,0xf,0);
    FUN_8025bac0(1,7,4,6,7);
    FUN_8025bef8(1,0,0);
    FUN_8025bb44(1,0,0,0,1,0);
    FUN_8025bc04(1,0,0,2,1,0);
    FUN_8025c2a0(2);
  }
  FUN_8025b6f0(0);
  FUN_80259ea4(4,0,0,0,0,0,2);
  FUN_80259ea4(5,0,0,0,0,0,2);
  FUN_80259e58(0);
  FUN_802581e0(1);
  FUN_80257f10(0,1,4,0x3c,0,0x7d);
  FUN_8004c264(iVar6,0);
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
  if ((param_6 & 0xff) == 0) {
    FUN_8025c584(1,4,5,5);
  }
  else {
    FUN_8025c584(1,4,1,5);
  }
  uVar2 = (uint)*(ushort *)(iVar6 + 10) * 4 * (param_5 & 0xffff);
  uVar3 = (uint)*(ushort *)(iVar6 + 0xc) * 4 * (param_5 & 0xffff);
  FUN_8025889c(0x80,1,4);
  write_volatile_1(DAT_cc008000,0x3c);
  sVar1 = (short)((int)uVar7 << 2);
  write_volatile_2(0xcc008000,sVar1);
  sVar5 = (short)(param_3 << 2);
  write_volatile_2(0xcc008000,sVar5);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_4(0xcc008000,FLOAT_803deedc);
  write_volatile_4(0xcc008000,FLOAT_803deedc);
  write_volatile_1(DAT_cc008000,0x3c);
  sVar4 = sVar1 + (short)(uVar2 >> 8) + (ushort)((int)uVar2 < 0 && (uVar2 & 0xff) != 0);
  write_volatile_2(0xcc008000,sVar4);
  write_volatile_2(0xcc008000,sVar5);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_4(0xcc008000,FLOAT_803deee4);
  write_volatile_4(0xcc008000,FLOAT_803deedc);
  write_volatile_1(DAT_cc008000,0x3c);
  write_volatile_2(0xcc008000,sVar4);
  sVar5 = sVar5 + (short)(uVar3 >> 8) + (ushort)((int)uVar3 < 0 && (uVar3 & 0xff) != 0);
  write_volatile_2(0xcc008000,sVar5);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_4(0xcc008000,FLOAT_803deee4);
  write_volatile_4(0xcc008000,FLOAT_803deee4);
  write_volatile_1(DAT_cc008000,0x3c);
  write_volatile_2(0xcc008000,sVar1);
  write_volatile_2(0xcc008000,sVar5);
  write_volatile_2(0xcc008000,0xfff8);
  write_volatile_4(0xcc008000,FLOAT_803deedc);
  write_volatile_4(0xcc008000,FLOAT_803deee4);
  FUN_8000fb00();
  FUN_80286124();
  return;
}

