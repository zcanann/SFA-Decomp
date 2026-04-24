// Function: FUN_802445a0
// Entry: 802445a0
// Size: 448 bytes

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_802445a0(void)

{
  uint uVar1;
  int iVar2;
  undefined auStack816 [12];
  int local_324;
  undefined auStack768 [12];
  int local_2f4;
  undefined auStack720 [712];
  
  FUN_8024377c();
  _DAT_817ffffc = 0;
  _DAT_817ffff8 = 0;
  DAT_800030e2 = 1;
  _DAT_812fdff0 = DAT_803dde50;
  _DAT_812fdfec = DAT_803dde54;
  FUN_80242474(auStack720);
  FUN_802422ac(auStack720);
  FUN_802491f4();
  FUN_8024b418(1);
  FUN_8024b854(&LAB_80244594);
  iVar2 = FUN_8024b770();
  if (iVar2 == 0) {
    FUN_80244860(_DAT_817ffffc);
  }
  FUN_80243b44(0xffffffe0);
  FUN_80243bcc(0x400);
  FUN_80243790();
  do {
  } while (DAT_803dde58 == 0);
  FUN_8024ad70(auStack768,&DAT_803ad3c0,0x20,0x2440,0);
  do {
    while( true ) {
      do {
      } while (local_2f4 == 1);
      if (local_2f4 < 1) break;
      if (local_2f4 < 0xc) {
LAB_802446a4:
        FUN_80244860(_DAT_817ffffc);
      }
    }
    if (local_2f4 == -1) goto LAB_802446a4;
  } while (local_2f4 < -1);
  uVar1 = DAT_803ad3d8 + 0x1fU & 0xffffffe0;
  do {
  } while (DAT_803dde58 == 0);
  FUN_8024ad70(auStack816,0x81300000,uVar1,DAT_803ad3d4 + 0x2460,0);
  do {
    while( true ) {
      do {
      } while (local_324 == 1);
      if (0 < local_324) break;
      if (local_324 == -1) goto LAB_80244728;
      if (-2 < local_324) {
        FUN_80241ae0(0x81300000,uVar1);
        FUN_80244554(0x81300000);
        return;
      }
    }
    if (local_324 < 0xc) {
LAB_80244728:
      FUN_80244860(_DAT_817ffffc);
    }
  } while( true );
}

