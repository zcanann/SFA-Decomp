// Function: FUN_802443c4
// Entry: 802443c4
// Size: 288 bytes

void FUN_802443c4(void)

{
  uint uVar1;
  undefined4 uVar2;
  
  uVar1 = DAT_800000f0;
  uVar2 = FUN_8024377c();
  if (uVar1 < 0x1800001) {
    FUN_802443ac(&LAB_802442ac);
  }
  else if (uVar1 < 0x3000001) {
    FUN_802443ac(&LAB_8024432c);
  }
  write_volatile_2(DAT_cc004020,0);
  write_volatile_2(DAT_cc004010,0xff);
  FUN_80243b44(0xf0000000);
  FUN_802437c8(0,&LAB_80244240);
  FUN_802437c8(1,&LAB_80244240);
  FUN_802437c8(2,&LAB_80244240);
  FUN_802437c8(3,&LAB_80244240);
  FUN_802437c8(4,&LAB_80244240);
  FUN_8024476c(&PTR_LAB_8032d808);
  if ((DAT_800000f0 < DAT_80000028) && (DAT_800000f0 == 0x1800000)) {
    write_volatile_2(DAT_cc004028,2);
  }
  FUN_80243bcc(0x8000000);
  FUN_802437a4(uVar2);
  return;
}

