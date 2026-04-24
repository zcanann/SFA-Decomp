// Function: FUN_800e8508
// Entry: 800e8508
// Size: 152 bytes

int FUN_800e8508(void)

{
  int iVar1;
  
  iVar1 = FUN_8007dbc0(&DAT_803a31c4);
  if ((iVar1 == 0) || (DAT_803a31c4 == '\0')) {
    FUN_800033a8(&DAT_803a31c4,0,0xe4);
    DAT_803a31ca = 0;
    DAT_803a31c6 = 1;
    DAT_803a31cc = 1;
    DAT_803a31c4 = '\x01';
    DAT_803a31ce = 0x7f;
    DAT_803a31cf = 0x7f;
    DAT_803a31d0 = 0x7f;
  }
  return iVar1;
}

