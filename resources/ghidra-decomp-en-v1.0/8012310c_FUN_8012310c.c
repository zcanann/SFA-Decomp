// Function: FUN_8012310c
// Entry: 8012310c
// Size: 248 bytes

void FUN_8012310c(void)

{
  if (DAT_803dd7a0 == '\0') {
    if ((DAT_803dd8d2 == 0) &&
       (DAT_803dd7a2 = DAT_803dd7a2 + (ushort)DAT_803db410 * -0x20, DAT_803dd7a2 < 0)) {
      DAT_803dd7a2 = 0;
    }
  }
  else {
    DAT_803dd7a2 = DAT_803dd7a2 + (ushort)DAT_803db410 * 0x20;
    if (0xff < DAT_803dd7a2) {
      DAT_803dd7a2 = 0xff;
    }
  }
  if ((DAT_803dd7a0 == '\0') || (DAT_803dd7a2 != 0xff)) {
    DAT_803dd8d2 = DAT_803dd8d2 + (ushort)DAT_803db410 * -4;
    if (DAT_803dd8d2 < 0) {
      DAT_803dd8d2 = 0;
    }
  }
  else {
    DAT_803dd8d2 = DAT_803dd8d2 + (ushort)DAT_803db410 * 4;
    if (DAT_803dba68 < DAT_803dd8d2) {
      DAT_803dd8d2 = DAT_803dba68;
    }
  }
  if (DAT_803dd7a2 != 0) {
    return;
  }
  DAT_803dba6e = 0xffff;
  return;
}

