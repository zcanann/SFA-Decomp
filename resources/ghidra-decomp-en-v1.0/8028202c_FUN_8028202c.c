// Function: FUN_8028202c
// Entry: 8028202c
// Size: 68 bytes

undefined FUN_8028202c(uint param_1,uint param_2)

{
  if ((param_2 & 0xff) != 0xff) {
    return *(undefined *)((param_2 & 0xff) * 0x10 + -0x7fc328a0 + (param_1 & 0xff));
  }
  return (&DAT_803cd7e0)[param_1 & 0xff];
}

