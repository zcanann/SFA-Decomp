// Function: FUN_80282790
// Entry: 80282790
// Size: 68 bytes

undefined FUN_80282790(uint param_1,uint param_2)

{
  if ((param_2 & 0xff) != 0xff) {
    return *(undefined *)((param_2 & 0xff) * 0x10 + -0x7fc31c40 + (param_1 & 0xff));
  }
  return (&DAT_803ce440)[param_1 & 0xff];
}

