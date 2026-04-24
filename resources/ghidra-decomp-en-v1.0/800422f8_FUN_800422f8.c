// Function: FUN_800422f8
// Entry: 800422f8
// Size: 184 bytes

void FUN_800422f8(int param_1,undefined4 param_2)

{
  if (param_1 < 0) {
    FUN_80248c64(param_2);
    FUN_80024134(DAT_803dcc8c,param_2);
  }
  else {
    FUN_80248c64(param_2);
    FUN_80024134(DAT_803dcc8c,param_2);
    if ((DAT_803dcc80 & 0x20000000) == 0) {
      if ((DAT_803dcc80 & 0x80000000) != 0) {
        DAT_803dcc84 = DAT_803dcc84 | 0x80000000;
        DAT_803460c8 = 0;
      }
    }
    else {
      DAT_803dcc84 = DAT_803dcc84 | 0x20000000;
      DAT_80345fa8 = 0;
    }
  }
  return;
}

