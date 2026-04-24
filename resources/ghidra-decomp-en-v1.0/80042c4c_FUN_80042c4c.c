// Function: FUN_80042c4c
// Entry: 80042c4c
// Size: 184 bytes

void FUN_80042c4c(int param_1,undefined4 param_2)

{
  if (param_1 < 0) {
    FUN_80248c64(param_2);
    FUN_80024134(DAT_803dcc8c,param_2);
  }
  else {
    FUN_80248c64(param_2);
    FUN_80024134(DAT_803dcc8c,param_2);
    if ((DAT_803dcc80 & 1) == 0) {
      if ((DAT_803dcc80 & 2) != 0) {
        DAT_803dcc84 = DAT_803dcc84 | 2;
        DAT_80346088 = 0;
      }
    }
    else {
      DAT_803dcc84 = DAT_803dcc84 | 1;
      DAT_8034601c = 0;
    }
  }
  return;
}

