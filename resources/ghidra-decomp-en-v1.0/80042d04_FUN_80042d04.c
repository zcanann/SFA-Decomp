// Function: FUN_80042d04
// Entry: 80042d04
// Size: 184 bytes

void FUN_80042d04(int param_1,undefined4 param_2)

{
  if (param_1 < 0) {
    FUN_80248c64(param_2);
    FUN_80024134(DAT_803dcc8c,param_2);
  }
  else {
    FUN_80248c64(param_2);
    FUN_80024134(DAT_803dcc8c,param_2);
    if ((DAT_803dcc80 & 0x40) == 0) {
      if ((DAT_803dcc80 & 0x80) != 0) {
        DAT_803dcc84 = DAT_803dcc84 | 0x80;
        DAT_80346094 = 0;
      }
    }
    else {
      DAT_803dcc84 = DAT_803dcc84 | 0x40;
      DAT_8034602c = 0;
    }
  }
  return;
}

