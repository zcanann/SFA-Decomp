// Function: FUN_80282514
// Entry: 80282514
// Size: 60 bytes

undefined * FUN_80282514(uint param_1,uint param_2)

{
  if ((param_2 & 0xff) == 0xff) {
    return &DAT_803d4b80 + (param_1 & 0xff);
  }
  return (undefined *)((param_2 & 0xff) * 0x10 + -0x7fc2b500 + (param_1 & 0xff));
}

