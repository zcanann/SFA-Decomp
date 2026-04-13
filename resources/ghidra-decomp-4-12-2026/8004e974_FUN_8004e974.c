// Function: FUN_8004e974
// Entry: 8004e974
// Size: 1748 bytes

void FUN_8004e974(undefined4 *param_1)

{
  float fVar1;
  float *pfVar2;
  undefined4 local_100;
  float local_fc;
  float local_f8;
  int local_f4;
  int local_f0;
  float local_ec;
  undefined4 local_e8;
  undefined4 local_e4;
  undefined4 local_e0;
  undefined4 local_dc;
  undefined4 local_d8;
  float afStack_d4 [12];
  float local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  float local_88;
  float local_84;
  float local_80;
  float local_7c;
  float local_78;
  float local_74;
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
  
  local_ec = DAT_802c24e8;
  local_e8 = DAT_802c24ec;
  local_e4 = DAT_802c24f0;
  local_e0 = DAT_802c24f4;
  local_dc = DAT_802c24f8;
  local_d8 = DAT_802c24fc;
  pfVar2 = (float *)FUN_8000f578();
  local_44 = FLOAT_803df74c;
  local_40 = FLOAT_803df74c;
  local_3c = FLOAT_803df744 / FLOAT_803dd9bc;
  local_38 = FLOAT_803dd9b8;
  fVar1 = FLOAT_803df744 / (FLOAT_803dd9c4 - FLOAT_803dd9c0);
  local_34 = fVar1 * pfVar2[4];
  local_30 = fVar1 * pfVar2[5];
  local_2c = fVar1 * pfVar2[6];
  local_28 = fVar1 * pfVar2[7] + -FLOAT_803dd9c4 * fVar1;
  local_24 = FLOAT_803df74c;
  local_20 = FLOAT_803df74c;
  local_1c = FLOAT_803df74c;
  local_18 = FLOAT_803df748;
  FUN_8025d8c4(&local_44,DAT_803dda00,0);
  FUN_80258674(DAT_803dda08,0,0,0,0,DAT_803dda00);
  local_100 = *param_1;
  FUN_8025c510(DAT_803dd9f4,(byte *)&local_100);
  FUN_8006c6a4(&local_f0);
  if (local_f0 != 0) {
    if (*(char *)(local_f0 + 0x48) == '\0') {
      FUN_8025b054((uint *)(local_f0 + 0x20),DAT_803dda0c);
    }
    else {
      FUN_8025aeac((uint *)(local_f0 + 0x20),*(uint **)(local_f0 + 0x40),DAT_803dda0c);
    }
  }
  if (DAT_803dd9b1 == '\0') {
    FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,0xff);
    FUN_8025c1a4(DAT_803dda10,0,0xe,9,0xf);
    FUN_8025c224(DAT_803dda10,7,7,7,0);
    FUN_8025c65c(DAT_803dda10,0,0);
    FUN_8025be80(DAT_803dda10);
    FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
    FUN_8025c368(DAT_803dda10,0,0,0,1,0);
    DAT_803dd9b0 = 1;
    FUN_8025c584(DAT_803dda10,DAT_803dd9f0);
    DAT_803dda08 = DAT_803dda08 + 1;
    DAT_803dda10 = DAT_803dda10 + 1;
    DAT_803dda0c = DAT_803dda0c + 1;
    DAT_803dda00 = DAT_803dda00 + 3;
    DAT_803dd9ea = DAT_803dd9ea + '\x01';
    DAT_803dd9e9 = DAT_803dd9e9 + '\x01';
  }
  else {
    FUN_8006cc38(&local_f8,&local_fc);
    local_fc = local_fc * FLOAT_803df760;
    local_f8 = local_f8 * FLOAT_803df788;
    FUN_8025b9e8(2,&local_ec,-2);
    FUN_8025bd1c(DAT_803dd9fc,DAT_803dda08 + 1,DAT_803dda0c + 1);
    local_74 = FLOAT_803dd9b4;
    local_70 = FLOAT_803df74c;
    local_6c = FLOAT_803df74c;
    local_68 = FLOAT_803dda58 * FLOAT_803dd9b4 + local_f8;
    local_64 = FLOAT_803df74c;
    local_60 = FLOAT_803dd9b4;
    local_5c = FLOAT_803df74c;
    local_58 = FLOAT_803df74c;
    local_54 = FLOAT_803df74c;
    local_50 = FLOAT_803df74c;
    local_4c = FLOAT_803df74c;
    local_48 = FLOAT_803df748;
    FUN_8024782c((double)FLOAT_803df7a8,afStack_d4,0x7a);
    FUN_80247618(afStack_d4,&local_74,&local_74);
    FUN_80247618(&local_74,pfVar2,&local_74);
    FUN_8025d8c4(&local_74,DAT_803dda00 + 3,0);
    FUN_80258674(DAT_803dda08 + 1,0,0,0,0,DAT_803dda00 + 3);
    FUN_8025b94c(DAT_803dda10,DAT_803dd9fc,0,2,2,6,6,0,0,0);
    FUN_8025bb48(DAT_803dd9fc,0,0);
    FUN_8025bd1c(DAT_803dd9fc + 1,DAT_803dda08 + 2,DAT_803dda0c + 1);
    local_a4 = FLOAT_803df74c;
    local_a0 = FLOAT_803df74c;
    local_9c = FLOAT_803dd9b4;
    local_98 = FLOAT_803dda5c * FLOAT_803dd9b4 + local_fc;
    local_94 = FLOAT_803df74c;
    local_90 = FLOAT_803dd9b4;
    local_8c = FLOAT_803df74c;
    local_88 = FLOAT_803df74c;
    local_84 = FLOAT_803df74c;
    local_80 = FLOAT_803df74c;
    local_7c = FLOAT_803df74c;
    local_78 = FLOAT_803df748;
    FUN_8024782c((double)FLOAT_803df7ac,afStack_d4,0x78);
    FUN_80247618(afStack_d4,&local_a4,&local_a4);
    FUN_80247618(&local_a4,pfVar2,&local_a4);
    FUN_8025d8c4(&local_a4,DAT_803dda00 + 6,0);
    FUN_80258674(DAT_803dda08 + 2,0,0,0,0,DAT_803dda00 + 6);
    FUN_8025b94c(DAT_803dda10 + 1,DAT_803dd9fc + 1,0,2,2,0,0,1,0,0);
    FUN_8025bb48(DAT_803dd9fc + 1,0,0);
    FUN_8025c828(DAT_803dda10,0xff,0xff,0xff);
    FUN_8025c1a4(DAT_803dda10,0xf,0xf,0xf,0);
    FUN_8025c224(DAT_803dda10,7,7,7,0);
    FUN_8025c65c(DAT_803dda10,0,0);
    FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
    FUN_8025c368(DAT_803dda10,0,0,0,1,0);
    DAT_803dd9b0 = 1;
    FUN_8025c828(DAT_803dda10 + 1,DAT_803dda08,DAT_803dda0c,0xff);
    FUN_8025c1a4(DAT_803dda10 + 1,0,0xe,9,0xf);
    FUN_8025c224(DAT_803dda10 + 1,7,7,7,0);
    FUN_8025c65c(DAT_803dda10 + 1,0,0);
    FUN_8025c2a8(DAT_803dda10 + 1,0,0,0,1,0);
    FUN_8025c368(DAT_803dda10 + 1,0,0,0,1,0);
    FUN_8006c760(&local_f4);
    if (local_f4 != 0) {
      if (*(char *)(local_f4 + 0x48) == '\0') {
        FUN_8025b054((uint *)(local_f4 + 0x20),DAT_803dda0c + 1);
      }
      else {
        FUN_8025aeac((uint *)(local_f4 + 0x20),*(uint **)(local_f4 + 0x40),DAT_803dda0c + 1);
      }
    }
    FUN_8025c584(DAT_803dda10 + 1,DAT_803dd9f0);
    DAT_803dda08 = DAT_803dda08 + 3;
    DAT_803dda10 = DAT_803dda10 + 2;
    DAT_803dda0c = DAT_803dda0c + 2;
    DAT_803dda00 = DAT_803dda00 + 9;
    DAT_803dd9fc = DAT_803dd9fc + 2;
    DAT_803dd9ea = DAT_803dd9ea + '\x02';
    DAT_803dd9e9 = DAT_803dd9e9 + '\x03';
    DAT_803dd9e8 = DAT_803dd9e8 + '\x02';
  }
  DAT_803dd9f4 = DAT_803dd9f4 + 1;
  DAT_803dd9f0 = DAT_803dd9f0 + 1;
  DAT_803dd9ec = DAT_803dd9ec + 1;
  return;
}

