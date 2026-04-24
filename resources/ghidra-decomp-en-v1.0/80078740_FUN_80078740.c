// Function: FUN_80078740
// Entry: 80078740
// Size: 204 bytes

void FUN_80078740(void)

{
  if ((((DAT_803dd018 != '\x01') || (DAT_803dd014 != 3)) || (DAT_803dd012 != '\x01')) ||
     (DAT_803dd01a == '\0')) {
    FUN_8025c708(1,3,1);
    DAT_803dd018 = '\x01';
    DAT_803dd014 = 3;
    DAT_803dd012 = '\x01';
    DAT_803dd01a = '\x01';
  }
  FUN_8025c584(0,1,0,5);
  if ((DAT_803dd011 != '\x01') || (DAT_803dd019 == '\0')) {
    FUN_8025c780(1);
    DAT_803dd011 = '\x01';
    DAT_803dd019 = '\x01';
  }
  FUN_8025bff0(7,0,0,7,0);
  return;
}

