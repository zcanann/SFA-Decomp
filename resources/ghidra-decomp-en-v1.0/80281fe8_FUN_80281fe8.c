// Function: FUN_80281fe8
// Entry: 80281fe8
// Size: 68 bytes

void FUN_80281fe8(uint param_1,uint param_2,undefined param_3)

{
  if ((param_2 & 0xff) != 0xff) {
    *(undefined *)((param_2 & 0xff) * 0x10 + -0x7fc328a0 + (param_1 & 0xff)) = param_3;
    return;
  }
  (&DAT_803cd7e0)[param_1 & 0xff] = param_3;
  return;
}

