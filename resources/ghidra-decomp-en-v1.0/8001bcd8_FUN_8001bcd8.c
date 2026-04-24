// Function: FUN_8001bcd8
// Entry: 8001bcd8
// Size: 60 bytes

undefined4 FUN_8001bcd8(int param_1)

{
  undefined4 uVar1;
  
  uVar1 = DAT_803dca00;
  DAT_803dca00 = param_1;
  if (param_1 == 0) {
    FUN_8001b700();
  }
  return uVar1;
}

