// Function: FUN_80251770
// Entry: 80251770
// Size: 64 bytes

void FUN_80251770(void)

{
  ushort uVar1;
  
  FUN_80243e74();
  uVar1 = DAT_cc00500a;
  DAT_cc00500a = uVar1 & 0xff57 | 4;
  FUN_80243e9c();
  return;
}

