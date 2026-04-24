// Function: FUN_80250ed0
// Entry: 80250ed0
// Size: 16 bytes

ushort FUN_80250ed0(void)

{
  ushort uVar1;
  
  uVar1 = read_volatile_2(DAT_cc005004);
  return uVar1 >> 0xf;
}

