// Function: FUN_802134b8
// Entry: 802134b8
// Size: 176 bytes

undefined4 FUN_802134b8(undefined4 param_1,int param_2)

{
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e67b8,param_1,0xc,0);
    *(float *)(param_2 + 0x2a0) = FLOAT_803e6808;
  }
  if ((*(uint *)(DAT_803ddd58 + 0x314) & 1) != 0) {
    *(uint *)(DAT_803ddd58 + 0x314) = *(uint *)(DAT_803ddd58 + 0x314) & 0xfffffffe;
    *(uint *)(DAT_803ddd54 + 0x104) = *(uint *)(DAT_803ddd54 + 0x104) | 0x2000;
  }
  if ((*(uint *)(DAT_803ddd58 + 0x314) & 0x80) != 0) {
    *(uint *)(DAT_803ddd58 + 0x314) = *(uint *)(DAT_803ddd58 + 0x314) & 0xffffff7f;
    *(uint *)(DAT_803ddd54 + 0x104) = *(uint *)(DAT_803ddd54 + 0x104) | 0x40000;
  }
  return 0;
}

