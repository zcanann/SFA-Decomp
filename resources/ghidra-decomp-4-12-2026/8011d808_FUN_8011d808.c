// Function: FUN_8011d808
// Entry: 8011d808
// Size: 552 bytes

undefined4
FUN_8011d808(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  int iVar2;
  
  if (DAT_803de393 == '\0') {
    iVar1 = (**(code **)(*DAT_803dd720 + 0xc))();
    iVar2 = (**(code **)(*DAT_803dd720 + 0x14))();
    if (iVar1 == 1) {
      if (iVar2 == 0) {
        FUN_8000bb38(0,0x103);
        FUN_80014974(1);
        FUN_800207d0();
        FUN_80014b68(0,0x300);
      }
      else {
        FUN_8000bb38(0,0x104);
        DAT_803de392 = '\0';
        DAT_803de393 = '\x01';
        DAT_8031b986 = DAT_8031b986 | 0x1000;
        DAT_8031b9c2 = DAT_8031b9c2 | 0x1000;
        (**(code **)(*DAT_803dd720 + 0x2c))();
      }
    }
    else if (iVar1 == 0) {
      FUN_8000bb38(0,0x419);
      FUN_80014974(1);
      FUN_800207d0();
      FUN_80014b68(0,0x300);
    }
  }
  else if (DAT_803de393 == '\x01') {
    if (DAT_803de392 == '\0') {
      FUN_800e8954(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    }
    DAT_803de392 = (char)(int)((float)((double)CONCAT44(0x43300000,(int)DAT_803de392 ^ 0x80000000) -
                                      DOUBLE_803e2a78) + FLOAT_803dc074);
    if (FLOAT_803e2a70 <=
        (float)((double)CONCAT44(0x43300000,(int)DAT_803de392 ^ 0x80000000) - DOUBLE_803e2a78)) {
      DAT_803de393 = '\0';
      DAT_8031b986 = DAT_8031b986 & 0xefff;
      DAT_8031b9c2 = DAT_8031b9c2 & 0xefff;
      (**(code **)(*DAT_803dd720 + 0x2c))();
      (**(code **)(*DAT_803dd720 + 0x18))(0);
    }
  }
  DAT_803de390 = DAT_803de390 + (ushort)DAT_803dc070 * 8;
  if (0x8c < DAT_803de390) {
    DAT_803de390 = 0x8c;
  }
  return 0;
}

