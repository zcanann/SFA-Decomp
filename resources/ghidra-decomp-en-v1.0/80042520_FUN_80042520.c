// Function: FUN_80042520
// Entry: 80042520
// Size: 184 bytes

void FUN_80042520(int param_1,undefined4 param_2)

{
  if (param_1 < 0) {
    FUN_80248c64(param_2);
    FUN_80024134(DAT_803dcc8c,param_2);
  }
  else {
    FUN_80248c64(param_2);
    FUN_80024134(DAT_803dcc8c,param_2);
    if ((DAT_803dcc80 & 0x20000) == 0) {
      if ((DAT_803dcc80 & 0x80000) != 0) {
        DAT_803dcc84 = DAT_803dcc84 | 0x80000;
        DAT_80346090 = 0;
      }
    }
    else {
      DAT_803dcc84 = DAT_803dcc84 | 0x20000;
      DAT_80346008 = 0;
    }
  }
  return;
}

