// Function: FUN_80243618
// Entry: 80243618
// Size: 88 bytes

ushort FUN_80243618(void)

{
  ushort uVar1;
  
  if (DAT_803dd1b0 < 2) {
    return DAT_803dd1b0;
  }
  if (DAT_800000cc == 0) {
    uVar1 = DAT_cc00206e;
    DAT_803dd1b0 = (ushort)((uVar1 & 2) != 0);
  }
  else {
    DAT_803dd1b0 = 0;
  }
  return DAT_803dd1b0;
}

