// Function: FUN_802543bc
// Entry: 802543bc
// Size: 276 bytes

void FUN_802543bc(void)

{
  uint uVar1;
  
  FUN_80243b44(0x7f8000);
  write_volatile_4(DAT_cc006800,0);
  write_volatile_4(DAT_cc006814,0);
  write_volatile_4(DAT_cc006828,0);
  write_volatile_4(DAT_cc006800,0x2000);
  FUN_802437c8(9,&LAB_8025400c);
  FUN_802437c8(10,&LAB_802540d4);
  FUN_802437c8(0xb,&LAB_802542ec);
  FUN_802437c8(0xc,&LAB_8025400c);
  FUN_802437c8(0xd,&LAB_802540d4);
  FUN_802437c8(0xe,&LAB_802542ec);
  FUN_802437c8(0xf,&LAB_8025400c);
  FUN_802437c8(0x10,&LAB_802540d4);
  uVar1 = FUN_802403d8();
  if ((uVar1 & 0x10000000) != 0) {
    DAT_800030c4 = 0;
    DAT_800030c0 = 0;
    DAT_803ae460 = 0;
    DAT_803ae420 = 0;
    FUN_80253960(0);
    FUN_80253960(1);
  }
  return;
}

