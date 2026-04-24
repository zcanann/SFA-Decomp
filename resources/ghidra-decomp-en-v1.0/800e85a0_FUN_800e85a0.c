// Function: FUN_800e85a0
// Entry: 800e85a0
// Size: 204 bytes

void FUN_800e85a0(char param_1)

{
  DAT_803a32c9 = 0;
  DAT_803db890 = param_1;
  if (DAT_803a32ca == '\0') {
    FUN_80003494(DAT_803dd498,&DAT_803a32a8,0x564);
    if (DAT_803dd49c != 0) {
      FUN_80003494(DAT_803dd49c,&DAT_803a32a8,0x564);
    }
  }
  if (DAT_803db890 == -1) {
    DAT_803db890 = '\0';
  }
  if (*DAT_803dd498 < '\x01') {
    *DAT_803dd498 = '\x01';
  }
  if (DAT_803dd498[0xc] < '\x01') {
    DAT_803dd498[0xc] = '\x01';
  }
  FUN_8007db24(DAT_803db890,DAT_803dd498,&DAT_803a31c4);
  return;
}

