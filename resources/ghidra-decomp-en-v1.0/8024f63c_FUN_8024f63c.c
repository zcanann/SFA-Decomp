// Function: FUN_8024f63c
// Entry: 8024f63c
// Size: 124 bytes

bool FUN_8024f63c(int param_1)

{
  byte bVar1;
  
  FUN_8024377c();
  bVar1 = DAT_800030e3 & 0x40;
  DAT_800030e3 = DAT_800030e3 & 0xbf;
  if (param_1 != 0) {
    DAT_800030e3 = DAT_800030e3 | 0x40;
  }
  FUN_802437a4();
  return bVar1 != 0;
}

