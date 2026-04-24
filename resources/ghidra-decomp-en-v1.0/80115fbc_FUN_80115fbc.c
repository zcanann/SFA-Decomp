// Function: FUN_80115fbc
// Entry: 80115fbc
// Size: 288 bytes

undefined4 FUN_80115fbc(void)

{
  byte bVar1;
  
  bVar1 = DAT_803db410;
  FUN_8007d6dc(s_n_rareware_8031a1c8);
  if (3 < bVar1) {
    bVar1 = 3;
  }
  if ('\0' < DAT_803dd609) {
    DAT_803dd609 = DAT_803dd609 - bVar1;
  }
  if (DAT_803dd608 != '\0') {
    FUN_800200e8(0x44f,0);
    FUN_80014948(4);
  }
  DAT_803dd5f8 = DAT_803dd5f8 + (uint)DAT_803db410;
  if (0x26c < DAT_803dd5f8) {
    DAT_803dd60a = '\x01';
  }
  if (DAT_803dd60a != '\0') {
    (**(code **)(*DAT_803dca4c + 8))(0x1e,1);
    DAT_803dd609 = '-';
    DAT_803dd608 = '\x01';
  }
  if ('\0' < DAT_803dd5fc) {
    FLOAT_803dd604 = FLOAT_803dd604 - FLOAT_803db414;
  }
  if ('\x02' < DAT_803dd5fc) {
    FLOAT_803dd600 = FLOAT_803dd600 - FLOAT_803db414;
  }
  return 0;
}

