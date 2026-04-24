// Function: FUN_80119fac
// Entry: 80119fac
// Size: 304 bytes

void FUN_80119fac(int param_1,undefined param_2)

{
  if (param_1 == 0) {
    if (DAT_803db424 == '\0') {
      FUN_8000bb18(0,0x100);
      (**(code **)(*DAT_803dca4c + 8))(0x14,5);
      DAT_803dd6cf = 0x23;
      DAT_803dd6cc = 1;
    }
    else {
      FUN_8000bb18(0,0x419);
      FUN_8011a7e4(0);
    }
  }
  else {
    DAT_803dd6cd = 1;
    FUN_8000bb18(0,0x418);
    (**(code **)(*DAT_803dca4c + 8))(0x14,1);
    (**(code **)(*DAT_803dca70 + 0x1c))(0);
    (**(code **)(*DAT_803dca70 + 0x1c))(1);
    (**(code **)(*DAT_803dca70 + 0x1c))(2);
    (**(code **)(*DAT_803dca70 + 0x1c))(3);
    DAT_803dd6cf = 0x23;
    DAT_803dd6c4 = param_2;
  }
  return;
}

