// Function: FUN_8012434c
// Entry: 8012434c
// Size: 356 bytes

void FUN_8012434c(void)

{
  if (DAT_803dc6cd < '\0') {
    DAT_803de416 = DAT_803de416 + (ushort)DAT_803dc070 * -(short)DAT_803dc6cd;
    if (0 < DAT_803de416) {
      DAT_803de416 = 0;
      DAT_803dc6cd = '\0';
      DAT_803de40e = 0;
    }
  }
  else {
    DAT_803de416 = DAT_803de416 - (ushort)DAT_803dc070 * (short)DAT_803dc6cd;
    if (DAT_803de416 < 0) {
      DAT_803de416 = 0;
      DAT_803dc6cd = '\0';
      DAT_803de40e = 0;
    }
  }
  if (DAT_803de415 == '\0') {
    if ((DAT_803de556 == 0) &&
       (DAT_803de418 = DAT_803de418 + (ushort)DAT_803dc070 * -8, DAT_803de418 < 0)) {
      DAT_803de418 = 0;
    }
  }
  else {
    DAT_803de418 = DAT_803de418 + (ushort)DAT_803dc070 * 8;
    if (0xff < DAT_803de418) {
      DAT_803de418 = 0xff;
    }
  }
  if ((DAT_803de415 == '\0') || (DAT_803de418 < 0x41)) {
    DAT_803de556 = DAT_803de556 + (ushort)DAT_803dc070 * -0x10;
    if (DAT_803de556 < 0) {
      DAT_803de556 = 0;
    }
  }
  else {
    DAT_803de556 = DAT_803de556 + (ushort)DAT_803dc070 * 0x10;
    if (DAT_803dc6ce < DAT_803de556) {
      DAT_803de556 = DAT_803dc6ce;
    }
  }
  return;
}

