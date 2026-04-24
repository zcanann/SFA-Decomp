// Function: FUN_8024b770
// Entry: 8024b770
// Size: 228 bytes

undefined4 FUN_8024b770(void)

{
  uint uVar1;
  undefined4 uVar2;
  undefined4 unaff_r31;
  
  FUN_8024377c();
  if (DAT_803ddf20 == 0) {
    if (DAT_803ddf18 == 0) {
      if (DAT_803ddf08 == (undefined *)0x0) {
        uVar2 = 0;
      }
      else if (DAT_803ddf08 == &DAT_803adf80) {
        uVar2 = 0;
      }
      else {
        uVar2 = *(undefined4 *)(DAT_803ddf08 + 0xc);
      }
    }
    else {
      uVar2 = 8;
    }
  }
  else {
    uVar2 = 0xffffffff;
  }
  switch(uVar2) {
  case 0:
  case 8:
    uVar1 = read_volatile_4(DAT_cc006004);
    if (((uVar1 >> 2 & 1) == 0) && ((uVar1 & 1) == 0)) {
      unaff_r31 = 1;
    }
    else {
      unaff_r31 = 0;
    }
    break;
  case 1:
  case 2:
  case 9:
  case 10:
    unaff_r31 = 1;
    break;
  case 0xffffffff:
  case 3:
  case 4:
  case 5:
  case 6:
  case 7:
  case 0xb:
    unaff_r31 = 0;
  }
  FUN_802437a4();
  return unaff_r31;
}

