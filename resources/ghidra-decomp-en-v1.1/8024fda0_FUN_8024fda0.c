// Function: FUN_8024fda0
// Entry: 8024fda0
// Size: 124 bytes

bool FUN_8024fda0(int param_1)

{
  byte bVar1;
  
  FUN_80243e74();
  bVar1 = DAT_800030e3 & 0x40;
  DAT_800030e3 = DAT_800030e3 & 0xbf;
  if (param_1 != 0) {
    DAT_800030e3 = DAT_800030e3 | 0x40;
  }
  FUN_80243e9c();
  return bVar1 != 0;
}

