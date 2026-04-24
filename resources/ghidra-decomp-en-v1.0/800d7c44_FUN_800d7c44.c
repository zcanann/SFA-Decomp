// Function: FUN_800d7c44
// Entry: 800d7c44
// Size: 792 bytes

void FUN_800d7c44(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  uint local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  uint local_54;
  uint local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  uint local_3c;
  uint local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  uint local_24;
  longlong local_20;
  
  if (DAT_803dd42e == '\0') {
    if ((DAT_803dd42f == '\0') && (FLOAT_803e0568 <= FLOAT_803dd428)) {
      (**(code **)(*DAT_803dca4c + 0xc))(0x1e,DAT_803dd42c);
      FLOAT_803dd428 = FLOAT_803e0560;
    }
    FLOAT_803dd420 = FLOAT_803dd424 * FLOAT_803db414 + FLOAT_803dd420;
    if (FLOAT_803dd420 < FLOAT_803e0560) {
      FLOAT_803dd420 = FLOAT_803e0560;
      DAT_803dd42d = 1;
      if (DAT_803dd42c != 5) {
        DAT_803dd42d = 1;
        return;
      }
      FUN_800703bc(0xff);
      return;
    }
    if (FLOAT_803dd420 <= FLOAT_803e0558) {
      DAT_803dd42d = 0;
    }
    else {
      FLOAT_803dd420 = FLOAT_803e0558;
      DAT_803dd42d = 1;
      if (DAT_803dd42f == '\0') {
        FLOAT_803dd428 = FLOAT_803dd428 + FLOAT_803db414;
      }
      if (DAT_803dd42c != 5) {
        FUN_800703bc(0xff);
      }
    }
  }
  else {
    DAT_803dd42e = DAT_803dd42e + -1;
  }
  if (DAT_803dc950 == '\0') {
    if (DAT_803dd42c == 3) {
      FUN_800d7568(param_1,param_2,param_3,0xff,0xff,0xff);
    }
    else if (DAT_803dd42c < 3) {
      if (DAT_803dd42c == 1) {
        FUN_8025d3d4(&local_34,&local_30,&local_2c,&local_28);
        FUN_8025d324(0,0,0x280,0x1e0);
        local_20 = (longlong)(int)FLOAT_803dd420;
        local_38 = (int)FLOAT_803dd420 & 0xff;
        local_24 = local_38;
        FUN_800753b8(local_34,local_30,local_2c,local_28,&local_24);
        FUN_8025d324(local_34,local_30,local_2c,local_28);
      }
      else if (DAT_803dd42c != 0) {
        FUN_8025d3d4(&local_4c,&local_48,&local_44,&local_40);
        FUN_8025d324(0,0,0x280,0x1e0);
        local_20 = (longlong)(int)FLOAT_803dd420;
        local_50 = (int)FLOAT_803dd420 & 0xffU | 0xffffff00;
        local_3c = local_50;
        FUN_800753b8(local_4c,local_48,local_44,local_40,&local_3c);
        FUN_8025d324(local_4c,local_48,local_44,local_40);
      }
    }
    else if ((DAT_803dd42c != 5) && (DAT_803dd42c < 5)) {
      FUN_8025d3d4(&local_64,&local_60,&local_5c,&local_58);
      FUN_8025d324(0,0,0x280,0x1e0);
      local_20 = (longlong)(int)FLOAT_803dd420;
      local_68 = (int)FLOAT_803dd420 & 0xffU | 0xff000000;
      local_54 = local_68;
      FUN_800753b8(local_64,local_60,local_5c,local_58,&local_54);
      FUN_8025d324(local_64,local_60,local_5c,local_58);
    }
  }
  return;
}

