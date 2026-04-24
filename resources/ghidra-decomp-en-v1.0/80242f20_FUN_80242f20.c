// Function: FUN_80242f20
// Entry: 80242f20
// Size: 88 bytes

ushort FUN_80242f20(void)

{
  ushort uVar1;
  
  if (DAT_803dc548 < 2) {
    return DAT_803dc548;
  }
  if (DAT_800000cc == 0) {
    uVar1 = read_volatile_2(DAT_cc00206e);
    DAT_803dc548 = (ushort)((uVar1 & 2) != 0);
  }
  else {
    DAT_803dc548 = 0;
  }
  return DAT_803dc548;
}

