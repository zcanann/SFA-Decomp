// Function: FUN_80042b94
// Entry: 80042b94
// Size: 184 bytes

void FUN_80042b94(int param_1,undefined4 param_2)

{
  if (param_1 < 0) {
    FUN_80248c64(param_2);
    FUN_80024134(DAT_803dcc8c,param_2);
  }
  else {
    FUN_80248c64(param_2);
    FUN_80024134(DAT_803dcc8c,param_2);
    if ((DAT_803dcc80 & 0x10) == 0) {
      if ((DAT_803dcc80 & 0x20) != 0) {
        DAT_803dcc84 = DAT_803dcc84 | 0x20;
        DAT_80346098 = 0;
      }
    }
    else {
      DAT_803dcc84 = DAT_803dcc84 | 0x10;
      DAT_80346030 = 0;
    }
  }
  return;
}

