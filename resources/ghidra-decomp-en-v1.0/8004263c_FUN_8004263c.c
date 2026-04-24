// Function: FUN_8004263c
// Entry: 8004263c
// Size: 184 bytes

void FUN_8004263c(int param_1,undefined4 param_2)

{
  if (param_1 < 0) {
    FUN_80248c64(param_2);
    FUN_80024134(DAT_803dcc8c,param_2);
  }
  else {
    FUN_80248c64(param_2);
    FUN_80024134(DAT_803dcc8c,param_2);
    if ((DAT_803dcc80 & 0x10000) == 0) {
      if ((DAT_803dcc80 & 0x40000) != 0) {
        DAT_803dcc84 = DAT_803dcc84 | 0x40000;
        DAT_8034608c = 0;
      }
    }
    else {
      DAT_803dcc84 = DAT_803dcc84 | 0x10000;
      DAT_80346004 = 0;
    }
  }
  return;
}

