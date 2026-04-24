// Function: FUN_8024f7b4
// Entry: 8024f7b4
// Size: 28 bytes

uint FUN_8024f7b4(void)

{
  ushort uVar1;
  ushort uVar2;
  
  uVar1 = read_volatile_2(DAT_cc005030);
  uVar2 = read_volatile_2(DAT_cc005032);
  return (uVar1 & 0x3ff) << 0x10 | uVar2 & 0xffe0;
}

