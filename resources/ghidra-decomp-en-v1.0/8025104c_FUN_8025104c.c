// Function: FUN_8025104c
// Entry: 8025104c
// Size: 16 bytes

ushort FUN_8025104c(void)

{
  ushort uVar1;
  
  uVar1 = read_volatile_2(DAT_cc00500a);
  return uVar1 & 0x200;
}

