// Function: FUN_800e9e98
// Entry: 800e9e98
// Size: 108 bytes

void FUN_800e9e98(void)

{
  if (*DAT_803dd498 < '\x01') {
    *DAT_803dd498 = '\x01';
  }
  if (DAT_803dd498[0xc] < '\x01') {
    DAT_803dd498[0xc] = '\x01';
  }
  FUN_80003494(&DAT_803a32a8,DAT_803dd498,0x6ec);
  FUN_800e9be0();
  return;
}

