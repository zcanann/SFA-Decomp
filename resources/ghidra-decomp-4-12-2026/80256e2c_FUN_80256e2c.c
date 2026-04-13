// Function: FUN_80256e2c
// Entry: 80256e2c
// Size: 76 bytes

void FUN_80256e2c(uint param_1,uint param_2)

{
  *(uint *)(DAT_803dd210 + 0x10) = *(uint *)(DAT_803dd210 + 0x10) & 0xfffffffe | param_1 & 0xff;
  *(uint *)(DAT_803dd210 + 0x10) =
       *(uint *)(DAT_803dd210 + 0x10) & 0xfffffffd | (param_2 & 0xff) << 1;
  *(short *)(DAT_803ded2c + 4) = (short)*(undefined4 *)(DAT_803dd210 + 0x10);
  return;
}

