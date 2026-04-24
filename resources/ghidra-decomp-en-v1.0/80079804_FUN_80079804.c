// Function: FUN_80079804
// Entry: 80079804
// Size: 444 bytes

void FUN_80079804(void)

{
  uint local_8;
  uint local_4;
  
  FUN_8025b6f0(DAT_803dd008);
  if (DAT_803dd009 == '\0') {
    FUN_80259ea4(4,0,0,0,0,0,2);
    FUN_80259ea4(5,0,0,0,0,0,2);
    FUN_80259e58(0);
  }
  else {
    FUN_80259ea4(5,0,0,0,0,0,2);
    FUN_80259e58(1);
  }
  FUN_802581e0(DAT_803dd00a);
  if (DAT_803db679 != 0xff) {
    local_4 = local_4 & 0xffffff00 | (uint)DAT_803db679;
    local_8 = local_4;
    FUN_8025bdac(0,&local_8);
    FUN_8025be8c(DAT_803dd030,0x1c);
    FUN_8025c0c4(DAT_803dd030,0xff,0xff,0xff);
    FUN_8025b71c(DAT_803dd030);
    FUN_8025ba40(DAT_803dd030,0xf,0xf,0xf,0);
    FUN_8025bac0(DAT_803dd030,7,0,6,7);
    FUN_8025bef8(DAT_803dd030,0,0);
    FUN_8025bb44(DAT_803dd030,0,0,0,1,0);
    FUN_8025bc04(DAT_803dd030,0,0,0,1,0);
    DAT_803dd030 = DAT_803dd030 + 1;
    DAT_803dd00b = DAT_803dd00b + '\x01';
  }
  FUN_8025c2a0(DAT_803dd00b);
  if (DAT_803dd009 != '\0') {
    FUN_80259ea4(4,0,0,1,0,0,2);
  }
  return;
}

