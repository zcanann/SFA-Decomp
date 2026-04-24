// Function: FUN_8004288c
// Entry: 8004288c
// Size: 184 bytes

void FUN_8004288c(int param_1,undefined4 param_2)

{
  if (param_1 < 0) {
    FUN_80248c64(param_2);
    FUN_80024134(DAT_803dcc8c,param_2);
  }
  else {
    FUN_80248c64(param_2);
    FUN_80024134(DAT_803dcc8c,param_2);
    if ((DAT_803dcc80 & 0x1000) == 0) {
      if ((DAT_803dcc80 & 0x2000) != 0) {
        DAT_803dcc84 = DAT_803dcc84 | 0x2000;
        DAT_8034609c = 0;
      }
    }
    else {
      DAT_803dcc84 = DAT_803dcc84 | 0x1000;
      DAT_80345ff0 = 0;
    }
  }
  return;
}

