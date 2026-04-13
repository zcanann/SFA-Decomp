// Function: FUN_800ea188
// Entry: 800ea188
// Size: 324 bytes

void FUN_800ea188(undefined4 *param_1,undefined2 param_2,uint param_3,undefined param_4)

{
  if ((param_3 & 4) != 0) {
    DAT_803a3f2a = '\0';
  }
  if (DAT_803a3f2a == '\0') {
    if ((param_3 & 1) == 0) {
      (&DAT_803a458c)[(uint)DAT_803a3f28 * 4] = *param_1;
      (&DAT_803a4590)[(uint)DAT_803a3f28 * 4] = param_1[1];
      (&DAT_803a4594)[(uint)DAT_803a3f28 * 4] = param_1[2];
      (&DAT_803a4598)[(uint)DAT_803a3f28 * 0x10] = (char)((ushort)param_2 >> 8);
      (&DAT_803a4599)[(uint)DAT_803a3f28 * 0x10] = param_4;
      FUN_80003494(DAT_803de110,0x803a3f08,0x6ec);
      if (DAT_803de114 != 0) {
        FUN_800238c4(DAT_803de114);
        DAT_803de114 = 0;
      }
    }
    else {
      FUN_80003494(DAT_803de110,0x803a3f08,0x5d8);
      if (DAT_803de114 != 0) {
        FUN_80003494(DAT_803de114,0x803a3f08,0x5d8);
      }
    }
    if ((param_3 & 2) != 0) {
      DAT_803a3f2a = '\x01';
    }
  }
  return;
}

