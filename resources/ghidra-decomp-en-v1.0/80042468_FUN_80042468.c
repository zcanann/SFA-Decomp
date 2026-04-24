// Function: FUN_80042468
// Entry: 80042468
// Size: 184 bytes

void FUN_80042468(int param_1,undefined4 param_2)

{
  if (param_1 < 0) {
    FUN_80248c64(param_2);
    FUN_80024134(DAT_803dcc8c,param_2);
  }
  else {
    FUN_80248c64(param_2);
    FUN_80024134(DAT_803dcc8c,param_2);
    if ((DAT_803dcc80 & 0x2000000) == 0) {
      if ((DAT_803dcc80 & 0x8000000) != 0) {
        DAT_803dcc84 = DAT_803dcc84 | 0x8000000;
        DAT_803460bc = 0;
      }
    }
    else {
      DAT_803dcc84 = DAT_803dcc84 | 0x2000000;
      DAT_80345fd8 = 0;
    }
  }
  return;
}

