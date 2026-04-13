// Function: FUN_8024ff18
// Entry: 8024ff18
// Size: 28 bytes

uint FUN_8024ff18(void)

{
  ushort uVar1;
  ushort uVar2;
  
  uVar1 = DAT_cc005030;
  uVar2 = DAT_cc005032;
  return (uVar1 & 0x3ff) << 0x10 | uVar2 & 0xffe0;
}

