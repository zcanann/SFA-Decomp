// Function: FUN_80254a5c
// Entry: 80254a5c
// Size: 112 bytes

undefined4 FUN_80254a5c(void)

{
  undefined4 uVar1;
  uint uVar2;
  
  if (DAT_803de0a4 == -0x5a00ffa6) {
    uVar1 = 0;
  }
  else {
    uVar2 = FUN_802403d8();
    if ((uVar2 & 0x10000000) == 0) {
      DAT_803de0a0 = 0;
      uVar1 = 2;
    }
    else {
      DAT_803de0a0 = 0xa5ff005a;
      DAT_803de098 = 0;
      uVar1 = 0;
      DAT_803de09c = 1;
    }
  }
  return uVar1;
}

