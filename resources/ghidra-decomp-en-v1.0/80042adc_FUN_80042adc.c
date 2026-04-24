// Function: FUN_80042adc
// Entry: 80042adc
// Size: 184 bytes

void FUN_80042adc(int param_1,undefined4 param_2)

{
  if (param_1 < 0) {
    FUN_80248c64(param_2);
    FUN_80024134(DAT_803dcc8c,param_2);
  }
  else {
    FUN_80248c64(param_2);
    FUN_80024134(DAT_803dcc8c,param_2);
    if ((DAT_803dcc80 & 0x100) == 0) {
      if ((DAT_803dcc80 & 0x200) != 0) {
        DAT_803dcc84 = DAT_803dcc84 | 0x200;
        DAT_803460a4 = 0;
      }
    }
    else {
      DAT_803dcc84 = DAT_803dcc84 | 0x100;
      DAT_80345ffc = 0;
    }
  }
  return;
}

