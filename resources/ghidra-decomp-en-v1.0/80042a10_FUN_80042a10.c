// Function: FUN_80042a10
// Entry: 80042a10
// Size: 204 bytes

void FUN_80042a10(int param_1,undefined4 param_2)

{
  if (param_1 < 0) {
    FUN_80248c64(param_2);
    FUN_80024134(DAT_803dcc8c,param_2);
    FUN_80023800(DAT_8035f478);
    DAT_8035f478 = 0;
    DAT_80346000 = 0;
    if ((DAT_803dcc80 & 0x400) != 0) {
      DAT_803dcc84 = DAT_803dcc84 | 0x400;
      DAT_80346000 = 0;
    }
  }
  else {
    FUN_80248c64(param_2);
    FUN_80024134(DAT_803dcc8c,param_2);
    if ((DAT_803dcc80 & 0x400) != 0) {
      DAT_803dcc84 = DAT_803dcc84 | 0x400;
      DAT_80346000 = 0;
    }
  }
  return;
}

