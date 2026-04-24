// Function: FUN_80250ec0
// Entry: 80250ec0
// Size: 16 bytes

ushort FUN_80250ec0(void)

{
  ushort uVar1;
  
  uVar1 = read_volatile_2(DAT_cc005000);
  return uVar1 >> 0xf;
}

