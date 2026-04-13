// Function: FUN_801233f0
// Entry: 801233f0
// Size: 248 bytes

void FUN_801233f0(void)

{
  if (DAT_803de420 == '\0') {
    if ((DAT_803de552 == 0) &&
       (DAT_803de422 = DAT_803de422 + (ushort)DAT_803dc070 * -0x20, DAT_803de422 < 0)) {
      DAT_803de422 = 0;
    }
  }
  else {
    DAT_803de422 = DAT_803de422 + (ushort)DAT_803dc070 * 0x20;
    if (0xff < DAT_803de422) {
      DAT_803de422 = 0xff;
    }
  }
  if ((DAT_803de420 == '\0') || (DAT_803de422 != 0xff)) {
    DAT_803de552 = DAT_803de552 + (ushort)DAT_803dc070 * -4;
    if (DAT_803de552 < 0) {
      DAT_803de552 = 0;
    }
  }
  else {
    DAT_803de552 = DAT_803de552 + (ushort)DAT_803dc070 * 4;
    if (DAT_803dc6d0 < DAT_803de552) {
      DAT_803de552 = DAT_803dc6d0;
    }
  }
  if (DAT_803de422 != 0) {
    return;
  }
  DAT_803dc6d6 = 0xffff;
  return;
}

