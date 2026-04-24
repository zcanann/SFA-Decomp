// Function: FUN_8024d97c
// Entry: 8024d97c
// Size: 60 bytes

ushort FUN_8024d97c(void)

{
  ushort uVar1;
  
  FUN_8024377c();
  uVar1 = read_volatile_2(DAT_cc00206e);
  FUN_802437a4();
  return uVar1 & 1;
}

