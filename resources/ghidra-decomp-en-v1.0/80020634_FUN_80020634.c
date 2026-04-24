// Function: FUN_80020634
// Entry: 80020634
// Size: 180 bytes

void FUN_80020634(int param_1,int param_2)

{
  if (param_1 == 0) {
    DAT_803dca3a = DAT_803dca3a + -1;
    if (DAT_803dca3a < '\x01') {
      DAT_803dca3c = 0;
      DAT_803dca3a = '\0';
      if (param_2 != 0) {
        FUN_8000b714(0);
      }
    }
  }
  else {
    FUN_80014a28();
    if ((DAT_803dca3a == '\0') && (param_2 != 0)) {
      FUN_8000b714(1);
    }
    DAT_803dca3a = DAT_803dca3a + '\x01';
    if ('\x02' < DAT_803dca3a) {
      DAT_803dca3a = '\x02';
    }
  }
  return;
}

