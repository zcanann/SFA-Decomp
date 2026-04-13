// Function: FUN_80076ef4
// Entry: 80076ef4
// Size: 1060 bytes

void FUN_80076ef4(undefined4 param_1,undefined4 param_2,int param_3,undefined4 *param_4,uint param_5
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
  
  uVar7 = FUN_8028683c();
  iVar6 = (int)((ulonglong)uVar7 >> 0x20);
  FUN_80257b5c();
  FUN_802570dc(0,1);
  FUN_802570dc(9,1);
  FUN_802570dc(0xd,1);
  *(char *)((int)param_4 + 3) = (char)((uint)*(byte *)((int)param_4 + 3) * (uint)DAT_803dc2d9 >> 8);
  local_28[0] = *param_4;
  FUN_8025c510(0,(byte *)local_28);
  FUN_8025c584(0,0xc);
  FUN_8025c5f0(0,0x1c);
  FUN_8025c828(0,0,0,0xff);
  FUN_8025be80(0);
  if ((param_6 & 0xff) == 0) {
    FUN_8025c1a4(0,0xf,0xe,8,0xf);
  }
  else {
    FUN_8025c1a4(0,0xf,0xf,0xf,0xe);
  }
  FUN_8025c224(0,7,4,6,7);
  FUN_8025c65c(0,0,0);
  FUN_8025c2a8(0,0,0,0,1,0);
  FUN_8025c368(0,0,0,2,1,0);
  if (*(int *)(iVar6 + 0x50) == 0) {
    FUN_8025ca04(1);
  }
  else {
    FUN_8025c5f0(1,0x1c);
    FUN_8025c828(0,0,1,0xff);
    FUN_8025c1a4(1,0xf,0xf,0xf,0);
    FUN_8025c224(1,7,4,6,7);
    FUN_8025c65c(1,0,0);
    FUN_8025c2a8(1,0,0,0,1,0);
    FUN_8025c368(1,0,0,2,1,0);
    FUN_8025ca04(2);
  }
  FUN_8025be54(0);
  FUN_8025a608(4,0,0,0,0,0,2);
  FUN_8025a608(5,0,0,0,0,0,2);
  FUN_8025a5bc(0);
  FUN_80258944(1);
  FUN_80258674(0,1,4,0x3c,0,0x7d);
  FUN_8004c3e0(iVar6,0);
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
  if ((param_6 & 0xff) == 0) {
    FUN_8025cce8(1,4,5,5);
  }
  else {
    FUN_8025cce8(1,4,1,5);
  }
  uVar2 = (uint)*(ushort *)(iVar6 + 10) * 4 * (param_5 & 0xffff);
  uVar3 = (uint)*(ushort *)(iVar6 + 0xc) * 4 * (param_5 & 0xffff);
  FUN_80259000(0x80,1,4);
  DAT_cc008000._0_1_ = 0x3c;
  sVar1 = (short)((int)uVar7 << 2);
  DAT_cc008000._0_2_ = sVar1;
  sVar5 = (short)(param_3 << 2);
  DAT_cc008000._0_2_ = sVar5;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000 = FLOAT_803dfb5c;
  DAT_cc008000 = FLOAT_803dfb5c;
  DAT_cc008000._0_1_ = 0x3c;
  sVar4 = sVar1 + (short)(uVar2 >> 8) + (ushort)((int)uVar2 < 0 && (uVar2 & 0xff) != 0);
  DAT_cc008000._0_2_ = sVar4;
  DAT_cc008000._0_2_ = sVar5;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000 = FLOAT_803dfb64;
  DAT_cc008000 = FLOAT_803dfb5c;
  DAT_cc008000._0_1_ = 0x3c;
  DAT_cc008000._0_2_ = sVar4;
  sVar5 = sVar5 + (short)(uVar3 >> 8) + (ushort)((int)uVar3 < 0 && (uVar3 & 0xff) != 0);
  DAT_cc008000._0_2_ = sVar5;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000 = FLOAT_803dfb64;
  DAT_cc008000 = FLOAT_803dfb64;
  DAT_cc008000._0_1_ = 0x3c;
  DAT_cc008000._0_2_ = sVar1;
  DAT_cc008000._0_2_ = sVar5;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000 = FLOAT_803dfb5c;
  DAT_cc008000 = FLOAT_803dfb64;
  FUN_8000fb20();
  FUN_80286888();
  return;
}

