// Function: FUN_80088c0c
// Entry: 80088c0c
// Size: 136 bytes

void FUN_80088c0c(void)

{
  undefined4 uVar1;
  
  if (DAT_803dd154 == 0) {
    uVar1 = FUN_8002bdf4(0x20,0x62b);
    DAT_803dd148 = FUN_8002df90(uVar1,4,0xffffffff,0xffffffff,0);
    uVar1 = FUN_8002bdf4(0x20,0x62c);
    DAT_803dd14c = FUN_8002df90(uVar1,4,0xffffffff,0xffffffff,0);
    DAT_803dd154 = 1;
    uVar1 = FUN_8002b588();
    FUN_8002853c(uVar1,FUN_80074110);
  }
  return;
}

