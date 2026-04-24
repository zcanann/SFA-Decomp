// Function: FUN_80042dbc
// Entry: 80042dbc
// Size: 184 bytes

void FUN_80042dbc(int param_1,undefined4 param_2)

{
  if (param_1 < 0) {
    FUN_80248c64(param_2);
    FUN_80024134(DAT_803dcc8c,param_2);
  }
  else {
    FUN_80248c64(param_2);
    FUN_80024134(DAT_803dcc8c,param_2);
    if ((DAT_803dcc80 & 4) == 0) {
      if ((DAT_803dcc80 & 8) != 0) {
        DAT_803dcc84 = DAT_803dcc84 | 8;
        DAT_80346084 = 0;
      }
    }
    else {
      DAT_803dcc84 = DAT_803dcc84 | 4;
      DAT_80346018 = 0;
    }
  }
  return;
}

