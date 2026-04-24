// Function: FUN_80124068
// Entry: 80124068
// Size: 356 bytes

void FUN_80124068(void)

{
  if (DAT_803dba65 < '\0') {
    DAT_803dd796 = DAT_803dd796 + (ushort)DAT_803db410 * -(short)DAT_803dba65;
    if (0 < DAT_803dd796) {
      DAT_803dd796 = 0;
      DAT_803dba65 = '\0';
      DAT_803dd78e = 0;
    }
  }
  else {
    DAT_803dd796 = DAT_803dd796 - (ushort)DAT_803db410 * (short)DAT_803dba65;
    if (DAT_803dd796 < 0) {
      DAT_803dd796 = 0;
      DAT_803dba65 = '\0';
      DAT_803dd78e = 0;
    }
  }
  if (DAT_803dd795 == '\0') {
    if ((DAT_803dd8d6 == 0) &&
       (DAT_803dd798 = DAT_803dd798 + (ushort)DAT_803db410 * -8, DAT_803dd798 < 0)) {
      DAT_803dd798 = 0;
    }
  }
  else {
    DAT_803dd798 = DAT_803dd798 + (ushort)DAT_803db410 * 8;
    if (0xff < DAT_803dd798) {
      DAT_803dd798 = 0xff;
    }
  }
  if ((DAT_803dd795 == '\0') || (DAT_803dd798 < 0x41)) {
    DAT_803dd8d6 = DAT_803dd8d6 + (ushort)DAT_803db410 * -0x10;
    if (DAT_803dd8d6 < 0) {
      DAT_803dd8d6 = 0;
    }
  }
  else {
    DAT_803dd8d6 = DAT_803dd8d6 + (ushort)DAT_803db410 * 0x10;
    if (DAT_803dba66 < DAT_803dd8d6) {
      DAT_803dd8d6 = DAT_803dba66;
    }
  }
  return;
}

