// Function: FUN_80256c08
// Entry: 80256c08
// Size: 152 bytes

void FUN_80256c08(undefined4 param_1)

{
  FUN_80243e74();
  FUN_80256d78();
  *(short *)(DAT_803ded2c + 0x3c) = (short)param_1;
  *(ushort *)(DAT_803ded2c + 0x3e) = (ushort)((uint)param_1 >> 0x10) & 0x3fff;
  *(uint *)(DAT_803dd210 + 8) = *(uint *)(DAT_803dd210 + 8) & 0xfffffffd | 2;
  *(uint *)(DAT_803dd210 + 8) = *(uint *)(DAT_803dd210 + 8) & 0xffffffdf | 0x20;
  *(short *)(DAT_803ded2c + 2) = (short)*(undefined4 *)(DAT_803dd210 + 8);
  DAT_803ded54 = param_1;
  FUN_80256d50();
  FUN_80243e9c();
  return;
}

