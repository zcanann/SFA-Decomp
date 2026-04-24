// Function: FUN_80281db0
// Entry: 80281db0
// Size: 60 bytes

undefined * FUN_80281db0(uint param_1,uint param_2)

{
  if ((param_2 & 0xff) == 0xff) {
    return &DAT_803d3f20 + (param_1 & 0xff);
  }
  return (undefined *)((param_2 & 0xff) * 0x10 + -0x7fc2c160 + (param_1 & 0xff));
}

