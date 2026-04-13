// Function: FUN_8028274c
// Entry: 8028274c
// Size: 68 bytes

void FUN_8028274c(uint param_1,uint param_2,undefined param_3)

{
  if ((param_2 & 0xff) != 0xff) {
    *(undefined *)((param_2 & 0xff) * 0x10 + -0x7fc31c40 + (param_1 & 0xff)) = param_3;
    return;
  }
  (&DAT_803ce440)[param_1 & 0xff] = param_3;
  return;
}

