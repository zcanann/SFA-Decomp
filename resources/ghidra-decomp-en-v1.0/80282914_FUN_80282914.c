// Function: FUN_80282914
// Entry: 80282914
// Size: 188 bytes

uint FUN_80282914(uint param_1,uint param_2,uint param_3,uint param_4)

{
  uint uVar1;
  
  uVar1 = (&DAT_803d3ca0)[(param_4 & 0xff) * 0x10 + (param_3 & 0xff)];
  if (((uint)(&PTR_DAT_8032fff0)[param_2 & 0xff] & uVar1) == 0) {
    uVar1 = (uint)*(ushort *)((param_1 & 0xff) * 0x90 + (param_2 & 0xff) * 0x24 + -0x7fc4256c);
  }
  else {
    (&DAT_803d3ca0)[(param_4 & 0xff) * 0x10 + (param_3 & 0xff)] =
         uVar1 & ~(uint)(&PTR_DAT_8032fff0)[param_2 & 0xff];
    uVar1 = FUN_80282070(0,&DAT_803bda74 + (param_2 & 0xff) * 0x24 + (param_1 & 0xff) * 0x90);
  }
  return uVar1;
}

