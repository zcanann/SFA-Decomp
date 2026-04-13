// Function: FUN_80251728
// Entry: 80251728
// Size: 72 bytes

void FUN_80251728(void)

{
  ushort uVar1;
  
  FUN_80243e74();
  uVar1 = DAT_cc00500a;
  DAT_cc00500a = uVar1 & 0xff57 | 0x801;
  DAT_803dece0 = 0;
  FUN_80243e9c();
  return;
}

