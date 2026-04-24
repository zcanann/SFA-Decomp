// Function: FUN_80256364
// Entry: 80256364
// Size: 100 bytes

void FUN_80256364(byte *param_1,byte *param_2,byte *param_3,byte *param_4,byte *param_5)

{
  *(uint *)(DAT_803dc5a8 + 0xc) = (uint)*DAT_803de0ac;
  *param_1 = (byte)*(undefined4 *)(DAT_803dc5a8 + 0xc) & 1;
  *param_2 = (byte)(*(uint *)(DAT_803dc5a8 + 0xc) >> 1) & 1;
  *param_3 = (byte)(*(uint *)(DAT_803dc5a8 + 0xc) >> 2) & 1;
  *param_4 = (byte)(*(uint *)(DAT_803dc5a8 + 0xc) >> 3) & 1;
  *param_5 = (byte)(*(uint *)(DAT_803dc5a8 + 0xc) >> 4) & 1;
  return;
}

