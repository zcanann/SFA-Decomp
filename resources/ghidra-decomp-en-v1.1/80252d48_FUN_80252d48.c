// Function: FUN_80252d48
// Entry: 80252d48
// Size: 108 bytes

uint FUN_80252d48(int param_1,int param_2)

{
  uint uVar1;
  
  FUN_80243e74();
  uVar1 = DAT_8032ee9c & 0xfc0000ff | param_1 << 0x10 | param_2 << 8;
  DAT_cc006430 = uVar1;
  DAT_8032ee9c = uVar1;
  FUN_80243e9c();
  return uVar1;
}

