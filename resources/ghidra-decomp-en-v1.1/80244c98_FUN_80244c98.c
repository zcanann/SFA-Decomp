// Function: FUN_80244c98
// Entry: 80244c98
// Size: 448 bytes

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_80244c98(void)

{
  uint uVar1;
  int iVar2;
  undefined4 auStack_330 [3];
  int local_324;
  undefined4 auStack_300 [3];
  int local_2f4;
  undefined auStack_2d0 [712];
  
  FUN_80243e74();
  _DAT_817ffffc = 0;
  _DAT_817ffff8 = 0;
  DAT_800030e2 = 1;
  _DAT_812fdff0 = DAT_803dead0;
  _DAT_812fdfec = DAT_803dead4;
  FUN_80242b6c((int)auStack_2d0);
  FUN_802429a4((uint)auStack_2d0);
  FUN_80249958();
  FUN_8024bb7c(1);
  FUN_8024bfb8(&LAB_80244c8c);
  iVar2 = FUN_8024bed4();
  if (iVar2 == 0) {
    FUN_80244f58(_DAT_817ffffc);
  }
  FUN_8024423c(0xffffffe0);
  FUN_802442c4(0x400);
  FUN_80243e88();
  do {
  } while (DAT_803dead8 == 0);
  FUN_8024b4d4(auStack_300,&DAT_803ae020,0x20,0x2440,0);
  do {
    while( true ) {
      do {
      } while (local_2f4 == 1);
      if (local_2f4 < 1) break;
      if (local_2f4 < 0xc) {
LAB_80244d9c:
        FUN_80244f58(_DAT_817ffffc);
      }
    }
    if (local_2f4 == -1) goto LAB_80244d9c;
  } while (local_2f4 < -1);
  uVar1 = DAT_803ae038 + 0x1fU & 0xffffffe0;
  do {
  } while (DAT_803dead8 == 0);
  FUN_8024b4d4(auStack_330,0x81300000,uVar1,DAT_803ae034 + 0x2460,0);
  do {
    while( true ) {
      do {
      } while (local_324 == 1);
      if (0 < local_324) break;
      if (local_324 == -1) goto LAB_80244e20;
      if (-2 < local_324) {
        FUN_802421d8(0x81300000,uVar1);
        FUN_80244c4c();
        return;
      }
    }
    if (local_324 < 0xc) {
LAB_80244e20:
      FUN_80244f58(_DAT_817ffffc);
    }
  } while( true );
}

