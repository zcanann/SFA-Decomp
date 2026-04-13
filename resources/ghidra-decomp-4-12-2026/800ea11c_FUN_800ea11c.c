// Function: FUN_800ea11c
// Entry: 800ea11c
// Size: 108 bytes

void FUN_800ea11c(void)

{
  if (*DAT_803de110 < '\x01') {
    *DAT_803de110 = '\x01';
  }
  if (DAT_803de110[0xc] < '\x01') {
    DAT_803de110[0xc] = '\x01';
  }
  FUN_80003494(0x803a3f08,(uint)DAT_803de110,0x6ec);
  FUN_800e9e64();
  return;
}

