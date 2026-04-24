// Function: FUN_80041d30
// Entry: 80041d30
// Size: 104 bytes

void FUN_80041d30(int param_1,undefined4 param_2)

{
  if (param_1 < 0) {
    FUN_80248c64(param_2);
    FUN_80024134(DAT_803dcc8c,param_2);
  }
  else {
    FUN_80248c64(param_2);
    FUN_80024134(DAT_803dcc8c,param_2);
    DAT_803dcc88 = DAT_803dcc88 + -1;
  }
  return;
}

