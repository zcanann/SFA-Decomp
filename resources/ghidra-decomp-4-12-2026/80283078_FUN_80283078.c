// Function: FUN_80283078
// Entry: 80283078
// Size: 188 bytes

uint FUN_80283078(uint param_1,uint param_2,uint param_3,uint param_4)

{
  uint uVar1;
  
  uVar1 = (&DAT_803d4900)[(param_4 & 0xff) * 0x10 + (param_3 & 0xff)];
  if (((uint)(&PTR_DAT_80330c50)[param_2 & 0xff] & uVar1) == 0) {
    uVar1 = (uint)*(ushort *)((param_1 & 0xff) * 0x90 + (param_2 & 0xff) * 0x24 + -0x7fc4190c);
  }
  else {
    (&DAT_803d4900)[(param_4 & 0xff) * 0x10 + (param_3 & 0xff)] =
         uVar1 & ~(uint)(&PTR_DAT_80330c50)[param_2 & 0xff];
    uVar1 = FUN_802827d4(0,&DAT_803be6d4 + (param_2 & 0xff) * 0x24 + (param_1 & 0xff) * 0x90,param_3
                         ,param_4);
  }
  return uVar1;
}

