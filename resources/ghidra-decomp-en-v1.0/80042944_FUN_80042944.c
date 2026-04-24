// Function: FUN_80042944
// Entry: 80042944
// Size: 204 bytes

void FUN_80042944(int param_1,undefined4 param_2)

{
  if (param_1 < 0) {
    FUN_80248c64(param_2);
    FUN_80024134(DAT_803dcc8c,param_2);
    FUN_80023800(DAT_8035f520);
    DAT_8035f520 = 0;
    DAT_803460a8 = 0;
    if ((DAT_803dcc80 & 0x800) != 0) {
      DAT_803dcc84 = DAT_803dcc84 | 0x800;
      DAT_803460a8 = 0;
    }
  }
  else {
    FUN_80248c64(param_2);
    FUN_80024134(DAT_803dcc8c,param_2);
    if ((DAT_803dcc80 & 0x800) != 0) {
      DAT_803dcc84 = DAT_803dcc84 | 0x800;
      DAT_803460a8 = 0;
    }
  }
  return;
}

