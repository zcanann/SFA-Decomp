// Function: FUN_80037048
// Entry: 80037048
// Size: 84 bytes

undefined4 * FUN_80037048(int param_1,int *param_2)

{
  if ((-1 < param_1) && (param_1 < 0x54)) {
    *param_2 = (uint)(byte)(&DAT_80343959)[param_1] - (uint)(byte)(&DAT_80343958)[param_1];
    return &DAT_80343558 + (byte)(&DAT_80343958)[param_1];
  }
  *param_2 = 0;
  return (undefined4 *)0x0;
}

