// Function: FUN_800e9f04
// Entry: 800e9f04
// Size: 324 bytes

void FUN_800e9f04(undefined4 *param_1,undefined2 param_2,uint param_3,undefined param_4)

{
  if ((param_3 & 4) != 0) {
    DAT_803a32ca = '\0';
  }
  if (DAT_803a32ca == '\0') {
    if ((param_3 & 1) == 0) {
      (&DAT_803a392c)[(uint)DAT_803a32c8 * 4] = *param_1;
      (&DAT_803a3930)[(uint)DAT_803a32c8 * 4] = param_1[1];
      (&DAT_803a3934)[(uint)DAT_803a32c8 * 4] = param_1[2];
      (&DAT_803a3938)[(uint)DAT_803a32c8 * 0x10] = (char)((ushort)param_2 >> 8);
      (&DAT_803a3939)[(uint)DAT_803a32c8 * 0x10] = param_4;
      FUN_80003494(DAT_803dd498,&DAT_803a32a8,0x6ec);
      if (DAT_803dd49c != 0) {
        FUN_80023800();
        DAT_803dd49c = 0;
      }
    }
    else {
      FUN_80003494(DAT_803dd498,&DAT_803a32a8,0x5d8);
      if (DAT_803dd49c != 0) {
        FUN_80003494(DAT_803dd49c,&DAT_803a32a8,0x5d8);
      }
    }
    if ((param_3 & 2) != 0) {
      DAT_803a32ca = '\x01';
    }
  }
  return;
}

