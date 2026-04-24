// Function: FUN_800427c0
// Entry: 800427c0
// Size: 204 bytes

void FUN_800427c0(int param_1,undefined4 param_2)

{
  if (param_1 < 0) {
    FUN_80248c64(param_2);
    FUN_80024134(DAT_803dcc8c,param_2);
    FUN_80023800(DAT_8035f520);
    DAT_8035f520 = 0;
    DAT_803460a8 = 0;
    if ((DAT_803dcc80 & 0x4000) != 0) {
      DAT_803dcc84 = DAT_803dcc84 | 0x4000;
      DAT_80345ff4 = 0;
    }
  }
  else {
    FUN_80248c64(param_2);
    FUN_80024134(DAT_803dcc8c,param_2);
    if ((DAT_803dcc80 & 0x4000) != 0) {
      DAT_803dcc84 = DAT_803dcc84 | 0x4000;
      DAT_80345ff4 = 0;
    }
  }
  return;
}

