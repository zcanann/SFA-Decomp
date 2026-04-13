// Function: FUN_80116258
// Entry: 80116258
// Size: 288 bytes

undefined4 FUN_80116258(void)

{
  byte bVar1;
  
  bVar1 = DAT_803dc070;
  FUN_8007d858();
  if (3 < bVar1) {
    bVar1 = 3;
  }
  if ('\0' < DAT_803de281) {
    DAT_803de281 = DAT_803de281 - bVar1;
  }
  if (DAT_803de280 != '\0') {
    FUN_800201ac(0x44f,0);
    FUN_80014974(4);
  }
  DAT_803de270 = DAT_803de270 + (uint)DAT_803dc070;
  if (0x26c < DAT_803de270) {
    DAT_803de282 = '\x01';
  }
  if (DAT_803de282 != '\0') {
    (**(code **)(*DAT_803dd6cc + 8))(0x1e,1);
    DAT_803de281 = '-';
    DAT_803de280 = '\x01';
  }
  if ('\0' < DAT_803de274) {
    FLOAT_803de27c = FLOAT_803de27c - FLOAT_803dc074;
  }
  if ('\x02' < DAT_803de274) {
    FLOAT_803de278 = FLOAT_803de278 - FLOAT_803dc074;
  }
  return 0;
}

