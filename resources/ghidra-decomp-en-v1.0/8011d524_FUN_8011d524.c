// Function: FUN_8011d524
// Entry: 8011d524
// Size: 552 bytes

undefined4 FUN_8011d524(void)

{
  int iVar1;
  int iVar2;
  
  if (DAT_803dd713 == '\0') {
    iVar1 = (**(code **)(*DAT_803dcaa0 + 0xc))();
    iVar2 = (**(code **)(*DAT_803dcaa0 + 0x14))();
    if (iVar1 == 1) {
      if (iVar2 == 0) {
        FUN_8000bb18(0,0x103);
        FUN_80014948(1);
        FUN_8002070c();
        FUN_80014b3c(0,0x300);
      }
      else {
        FUN_8000bb18(0,0x104);
        DAT_803dd712 = '\0';
        DAT_803dd713 = '\x01';
        DAT_8031ad36 = DAT_8031ad36 | 0x1000;
        DAT_8031ad72 = DAT_8031ad72 | 0x1000;
        (**(code **)(*DAT_803dcaa0 + 0x2c))();
      }
    }
    else if (iVar1 == 0) {
      FUN_8000bb18(0,0x419);
      FUN_80014948(1);
      FUN_8002070c();
      FUN_80014b3c(0,0x300);
    }
  }
  else if (DAT_803dd713 == '\x01') {
    if (DAT_803dd712 == '\0') {
      FUN_800e86d0();
    }
    DAT_803dd712 = (char)(int)((float)((double)CONCAT44(0x43300000,(int)DAT_803dd712 ^ 0x80000000) -
                                      DOUBLE_803e1df8) + FLOAT_803db414);
    if (FLOAT_803e1df0 <=
        (float)((double)CONCAT44(0x43300000,(int)DAT_803dd712 ^ 0x80000000) - DOUBLE_803e1df8)) {
      DAT_803dd713 = '\0';
      DAT_8031ad36 = DAT_8031ad36 & 0xefff;
      DAT_8031ad72 = DAT_8031ad72 & 0xefff;
      (**(code **)(*DAT_803dcaa0 + 0x2c))();
      (**(code **)(*DAT_803dcaa0 + 0x18))(0);
    }
  }
  DAT_803dd710 = DAT_803dd710 + (ushort)DAT_803db410 * 8;
  if (0x8c < DAT_803dd710) {
    DAT_803dd710 = 0x8c;
  }
  return 0;
}

