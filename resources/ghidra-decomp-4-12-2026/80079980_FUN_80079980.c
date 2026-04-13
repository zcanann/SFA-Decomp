// Function: FUN_80079980
// Entry: 80079980
// Size: 444 bytes

void FUN_80079980(void)

{
  undefined4 local_8;
  undefined4 local_4;
  
  FUN_8025be54((uint)DAT_803ddc88);
  if (DAT_803ddc89 == '\0') {
    FUN_8025a608(4,0,0,0,0,0,2);
    FUN_8025a608(5,0,0,0,0,0,2);
    FUN_8025a5bc(0);
  }
  else {
    FUN_8025a608(5,0,0,0,0,0,2);
    FUN_8025a5bc(1);
  }
  FUN_80258944((uint)DAT_803ddc8a);
  if (DAT_803dc2d9 != -1) {
    local_4 = CONCAT31(local_4._0_3_,DAT_803dc2d9);
    local_8 = local_4;
    FUN_8025c510(0,(byte *)&local_8);
    FUN_8025c5f0(DAT_803ddcb0,0x1c);
    FUN_8025c828(DAT_803ddcb0,0xff,0xff,0xff);
    FUN_8025be80(DAT_803ddcb0);
    FUN_8025c1a4(DAT_803ddcb0,0xf,0xf,0xf,0);
    FUN_8025c224(DAT_803ddcb0,7,0,6,7);
    FUN_8025c65c(DAT_803ddcb0,0,0);
    FUN_8025c2a8(DAT_803ddcb0,0,0,0,1,0);
    FUN_8025c368(DAT_803ddcb0,0,0,0,1,0);
    DAT_803ddcb0 = DAT_803ddcb0 + 1;
    DAT_803ddc8b = DAT_803ddc8b + 1;
  }
  FUN_8025ca04((uint)DAT_803ddc8b);
  if (DAT_803ddc89 != '\0') {
    FUN_8025a608(4,0,0,1,0,0,2);
  }
  return;
}

