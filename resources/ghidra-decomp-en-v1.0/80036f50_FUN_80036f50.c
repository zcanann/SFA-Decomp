// Function: FUN_80036f50
// Entry: 80036f50
// Size: 84 bytes

undefined4 * FUN_80036f50(int param_1,int *param_2)

{
  if ((-1 < param_1) && (param_1 < 0x54)) {
    *param_2 = (uint)(byte)(&DAT_80342cf9)[param_1] - (uint)(byte)(&DAT_80342cf8)[param_1];
    return &DAT_803428f8 + (byte)(&DAT_80342cf8)[param_1];
  }
  *param_2 = 0;
  return (undefined4 *)0x0;
}

