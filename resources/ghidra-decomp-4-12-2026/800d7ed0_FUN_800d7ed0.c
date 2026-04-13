// Function: FUN_800d7ed0
// Entry: 800d7ed0
// Size: 792 bytes

void FUN_800d7ed0(void)

{
  undefined4 local_68;
  int local_64;
  int local_60;
  int local_5c;
  int local_58;
  undefined4 local_54;
  undefined4 local_50;
  int local_4c;
  int local_48;
  int local_44;
  int local_40;
  undefined4 local_3c;
  uint local_38;
  int local_34;
  int local_30;
  int local_2c;
  int local_28;
  uint local_24;
  longlong local_20;
  
  if (DAT_803de0ae == '\0') {
    if ((DAT_803de0af == '\0') && (FLOAT_803e11e8 <= FLOAT_803de0a8)) {
      (**(code **)(*DAT_803dd6cc + 0xc))(0x1e,DAT_803de0ac);
      FLOAT_803de0a8 = FLOAT_803e11e0;
    }
    FLOAT_803de0a0 = FLOAT_803de0a4 * FLOAT_803dc074 + FLOAT_803de0a0;
    if (FLOAT_803de0a0 < FLOAT_803e11e0) {
      FLOAT_803de0a0 = FLOAT_803e11e0;
      DAT_803de0ad = 1;
      if (DAT_803de0ac != 5) {
        DAT_803de0ad = 1;
        return;
      }
      FUN_80070538(0xff);
      return;
    }
    if (FLOAT_803de0a0 <= FLOAT_803e11d8) {
      DAT_803de0ad = 0;
    }
    else {
      FLOAT_803de0a0 = FLOAT_803e11d8;
      DAT_803de0ad = 1;
      if (DAT_803de0af == '\0') {
        FLOAT_803de0a8 = FLOAT_803de0a8 + FLOAT_803dc074;
      }
      if (DAT_803de0ac != 5) {
        FUN_80070538(0xff);
      }
    }
  }
  else {
    DAT_803de0ae = DAT_803de0ae + -1;
  }
  if (DAT_803dd5d0 == '\0') {
    if (DAT_803de0ac == 3) {
      FUN_800d77f4();
    }
    else if (DAT_803de0ac < 3) {
      if (DAT_803de0ac == 1) {
        FUN_8025db38(&local_34,&local_30,&local_2c,&local_28);
        FUN_8025da88(0,0,0x280,0x1e0);
        local_20 = (longlong)(int)FLOAT_803de0a0;
        local_38 = (int)FLOAT_803de0a0 & 0xff;
        local_24 = local_38;
        FUN_80075534(local_34,local_30,local_2c,local_28,&local_24);
        FUN_8025da88(local_34,local_30,local_2c,local_28);
      }
      else if (DAT_803de0ac != 0) {
        FUN_8025db38(&local_4c,&local_48,&local_44,&local_40);
        FUN_8025da88(0,0,0x280,0x1e0);
        local_20 = (longlong)(int)FLOAT_803de0a0;
        local_50 = CONCAT31(0xffffff,(char)(int)FLOAT_803de0a0);
        local_3c = local_50;
        FUN_80075534(local_4c,local_48,local_44,local_40,&local_3c);
        FUN_8025da88(local_4c,local_48,local_44,local_40);
      }
    }
    else if ((DAT_803de0ac != 5) && (DAT_803de0ac < 5)) {
      FUN_8025db38(&local_64,&local_60,&local_5c,&local_58);
      FUN_8025da88(0,0,0x280,0x1e0);
      local_20 = (longlong)(int)FLOAT_803de0a0;
      local_68 = CONCAT31(0xff0000,(char)(int)FLOAT_803de0a0);
      local_54 = local_68;
      FUN_80075534(local_64,local_60,local_5c,local_58,&local_54);
      FUN_8025da88(local_64,local_60,local_5c,local_58);
    }
  }
  return;
}

