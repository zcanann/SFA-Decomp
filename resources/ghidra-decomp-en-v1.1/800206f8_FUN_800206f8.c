// Function: FUN_800206f8
// Entry: 800206f8
// Size: 180 bytes

void FUN_800206f8(int param_1,int param_2)

{
  if (param_1 == 0) {
    DAT_803dd6ba = DAT_803dd6ba + -1;
    if (DAT_803dd6ba < '\x01') {
      DAT_803dd6bc = 0;
      DAT_803dd6ba = '\0';
      if (param_2 != 0) {
        FUN_8000b734(0);
      }
    }
  }
  else {
    FUN_80014a54();
    if ((DAT_803dd6ba == '\0') && (param_2 != 0)) {
      FUN_8000b734(1);
    }
    DAT_803dd6ba = DAT_803dd6ba + '\x01';
    if ('\x02' < DAT_803dd6ba) {
      DAT_803dd6ba = '\x02';
    }
  }
  return;
}

