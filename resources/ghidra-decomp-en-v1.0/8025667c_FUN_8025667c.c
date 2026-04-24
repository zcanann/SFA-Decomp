// Function: FUN_8025667c
// Entry: 8025667c
// Size: 76 bytes

void FUN_8025667c(uint param_1,uint param_2)

{
  *(uint *)(DAT_803dc5a8 + 8) = *(uint *)(DAT_803dc5a8 + 8) & 0xfffffffb | (param_1 & 0xff) << 2;
  *(uint *)(DAT_803dc5a8 + 8) = *(uint *)(DAT_803dc5a8 + 8) & 0xfffffff7 | (param_2 & 0xff) << 3;
  *(short *)(DAT_803de0ac + 2) = (short)*(undefined4 *)(DAT_803dc5a8 + 8);
  return;
}

