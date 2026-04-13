// Function: FUN_80256744
// Entry: 80256744
// Size: 272 bytes

void FUN_80256744(uint *param_1)

{
  FUN_80243e74();
  DAT_803ded38 = param_1;
  if (param_1 == DAT_803ded3c) {
    *(uint *)(DAT_803ded28 + 0xc) = *param_1 & 0x3fffffff;
    *(uint *)(DAT_803ded28 + 0x10) = param_1[1] & 0x3fffffff;
    *(uint *)(DAT_803ded28 + 0x14) = param_1[6] & 0x3bffffe0;
    DAT_803ded44 = '\x01';
    FUN_80256e2c(1,1);
    FUN_80256de0(1,0);
    FUN_80256d9c('\x01');
  }
  else {
    if (DAT_803ded44 != '\0') {
      FUN_80256d9c('\0');
      DAT_803ded44 = '\0';
    }
    FUN_80256de0(0,0);
    *(uint *)(DAT_803ded28 + 0xc) = *param_1 & 0x3fffffff;
    *(uint *)(DAT_803ded28 + 0x10) = param_1[1] & 0x3fffffff;
    *(uint *)(DAT_803ded28 + 0x14) = param_1[6] & 0x3bffffe0;
  }
  sync(0);
  FUN_80243e9c();
  return;
}

