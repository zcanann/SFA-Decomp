// Function: FUN_802566c8
// Entry: 802566c8
// Size: 76 bytes

void FUN_802566c8(uint param_1,uint param_2)

{
  *(uint *)(DAT_803dc5a8 + 0x10) = *(uint *)(DAT_803dc5a8 + 0x10) & 0xfffffffe | param_1 & 0xff;
  *(uint *)(DAT_803dc5a8 + 0x10) =
       *(uint *)(DAT_803dc5a8 + 0x10) & 0xfffffffd | (param_2 & 0xff) << 1;
  *(short *)(DAT_803de0ac + 4) = (short)*(undefined4 *)(DAT_803dc5a8 + 0x10);
  return;
}

