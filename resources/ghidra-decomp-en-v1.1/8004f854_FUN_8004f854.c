// Function: FUN_8004f854
// Entry: 8004f854
// Size: 856 bytes

void FUN_8004f854(double param_1,undefined4 *param_2,float *param_3)

{
  double dVar1;
  double dVar2;
  undefined4 local_78;
  int local_74;
  float local_70;
  float local_6c;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  
  if (((DAT_803dd9f4 < 4) && (DAT_803dd9ea < 0xc)) && (DAT_803dd9e9 < 7)) {
    dVar1 = (double)FLOAT_803df75c;
    local_6c = (float)(dVar1 / param_1);
    dVar2 = (double)local_6c;
    local_3c = FLOAT_803df74c;
    local_38 = FLOAT_803df74c;
    local_34 = (float)(-(double)*param_3 * dVar2 + dVar1);
    local_30 = FLOAT_803df74c;
    local_2c = FLOAT_803df74c;
    local_24 = (float)(-(double)param_3[2] * dVar2 + dVar1);
    local_20 = FLOAT_803df74c;
    local_1c = FLOAT_803df74c;
    local_18 = FLOAT_803df74c;
    local_14 = FLOAT_803df748;
    local_70 = FLOAT_803df74c;
    local_68 = FLOAT_803df74c;
    local_64 = (float)(-(double)param_3[1] * dVar2 + dVar1);
    local_60 = FLOAT_803df74c;
    local_5c = FLOAT_803df74c;
    local_58 = FLOAT_803df74c;
    local_54 = FLOAT_803df75c;
    local_50 = FLOAT_803df74c;
    local_4c = FLOAT_803df74c;
    local_48 = FLOAT_803df74c;
    local_44 = FLOAT_803df748;
    local_40 = local_6c;
    local_28 = local_6c;
    FUN_8006c6bc(&local_74);
    FUN_8025d8c4(&local_40,DAT_803dda00,0);
    FUN_80258674(DAT_803dda08,0,0,0,0,DAT_803dda00);
    FUN_8025d8c4(&local_70,DAT_803dda00 + 3,0);
    FUN_80258674(DAT_803dda08 + 1,0,0,0,0,DAT_803dda00 + 3);
    FUN_8025be80(DAT_803dda10);
    FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,0xff);
    local_78 = *param_2;
    FUN_8025c510(DAT_803dd9f4,(byte *)&local_78);
    FUN_8025c584(DAT_803dda10,DAT_803dd9f0);
    FUN_8025c1a4(DAT_803dda10,0xf,0xe,8,0xf);
    FUN_8025c224(DAT_803dda10,7,7,7,0);
    FUN_8025c65c(DAT_803dda10,0,0);
    FUN_8025c2a8(DAT_803dda10,0,0,0,1,1);
    FUN_8025c368(DAT_803dda10,0,0,0,1,0);
    FUN_8025be80(DAT_803dda10 + 1);
    FUN_8025c828(DAT_803dda10 + 1,DAT_803dda08 + 1,DAT_803dda0c,0xff);
    FUN_8025c1a4(DAT_803dda10 + 1,0xf,2,8,0xf);
    FUN_8025c224(DAT_803dda10 + 1,7,7,7,0);
    FUN_8025c65c(DAT_803dda10 + 1,0,0);
    FUN_8025c2a8(DAT_803dda10 + 1,0,0,0,1,2);
    FUN_8025c368(DAT_803dda10 + 1,0,0,0,1,0);
    if (local_74 != 0) {
      if (*(char *)(local_74 + 0x48) == '\0') {
        FUN_8025b054((uint *)(local_74 + 0x20),DAT_803dda0c);
      }
      else {
        FUN_8025aeac((uint *)(local_74 + 0x20),*(uint **)(local_74 + 0x40),DAT_803dda0c);
      }
    }
    DAT_803dda10 = DAT_803dda10 + 2;
    DAT_803dda08 = DAT_803dda08 + 2;
    DAT_803dda0c = DAT_803dda0c + 1;
    DAT_803dd9f4 = DAT_803dd9f4 + 1;
    DAT_803dd9f0 = DAT_803dd9f0 + 1;
    DAT_803dd9ec = DAT_803dd9ec + 1;
    DAT_803dda00 = DAT_803dda00 + 6;
    DAT_803dd9e9 = DAT_803dd9e9 + 2;
    DAT_803dd9ea = DAT_803dd9ea + 2;
  }
  return;
}

