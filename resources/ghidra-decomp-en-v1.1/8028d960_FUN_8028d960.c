// Function: FUN_8028d960
// Entry: 8028d960
// Size: 224 bytes

void FUN_8028d960(int param_1)

{
  if (param_1 == 1) {
    FUN_8026c6b0();
    DAT_80332fc0 = &LAB_802861ac;
    DAT_80332fc4 = &LAB_80286224;
    DAT_80332fc8 = &LAB_80286278;
    DAT_80332fcc = &LAB_80286314;
    DAT_80332fd0 = &LAB_802863a0;
    DAT_80332fd4 = &DAT_80286600;
    DAT_80332fd8 = &DAT_80286604;
  }
  else {
    FUN_8026c6a8();
    DAT_80332fc0 = &DAT_8026c680;
    DAT_80332fc4 = &DAT_8026c684;
    DAT_80332fc8 = &LAB_8026c688;
    DAT_80332fcc = &LAB_8026c690;
    DAT_80332fd0 = &LAB_8026c698;
    DAT_80332fd4 = &DAT_8026c6a0;
    DAT_80332fd8 = &DAT_8026c6a4;
  }
  return;
}

