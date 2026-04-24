// Function: FUN_8004e7f8
// Entry: 8004e7f8
// Size: 1748 bytes

void FUN_8004e7f8(undefined4 *param_1)

{
  float fVar1;
  int iVar2;
  undefined4 local_100;
  float local_fc;
  float local_f8;
  int local_f4;
  int local_f0;
  undefined4 local_ec;
  undefined4 local_e8;
  undefined4 local_e4;
  undefined4 local_e0;
  undefined4 local_dc;
  undefined4 local_d8;
  undefined auStack212 [48];
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
  
  local_ec = DAT_802c1d68;
  local_e8 = DAT_802c1d6c;
  local_e4 = DAT_802c1d70;
  local_e0 = DAT_802c1d74;
  local_dc = DAT_802c1d78;
  local_d8 = DAT_802c1d7c;
  iVar2 = FUN_8000f558();
  local_44 = FLOAT_803deacc;
  local_40 = FLOAT_803deacc;
  local_3c = FLOAT_803deac4 / FLOAT_803dcd3c;
  local_38 = FLOAT_803dcd38;
  fVar1 = FLOAT_803deac4 / (FLOAT_803dcd44 - FLOAT_803dcd40);
  local_34 = fVar1 * *(float *)(iVar2 + 0x10);
  local_30 = fVar1 * *(float *)(iVar2 + 0x14);
  local_2c = fVar1 * *(float *)(iVar2 + 0x18);
  local_28 = fVar1 * *(float *)(iVar2 + 0x1c) + -FLOAT_803dcd44 * fVar1;
  local_24 = FLOAT_803deacc;
  local_20 = FLOAT_803deacc;
  local_1c = FLOAT_803deacc;
  local_18 = FLOAT_803deac8;
  FUN_8025d160(&local_44,DAT_803dcd80,0);
  FUN_80257f10(DAT_803dcd88,0,0,0,0,DAT_803dcd80);
  local_100 = *param_1;
  FUN_8025bdac(DAT_803dcd74,&local_100);
  FUN_8006c528(&local_f0);
  if (local_f0 != 0) {
    if (*(char *)(local_f0 + 0x48) == '\0') {
      FUN_8025a8f0(local_f0 + 0x20,DAT_803dcd8c);
    }
    else {
      FUN_8025a748(local_f0 + 0x20,*(undefined4 *)(local_f0 + 0x40));
    }
  }
  if (DAT_803dcd31 == '\0') {
    FUN_8025c0c4(DAT_803dcd90,DAT_803dcd88,DAT_803dcd8c,0xff);
    FUN_8025ba40(DAT_803dcd90,0,0xe,9,0xf);
    FUN_8025bac0(DAT_803dcd90,7,7,7,0);
    FUN_8025bef8(DAT_803dcd90,0,0);
    FUN_8025b71c(DAT_803dcd90);
    FUN_8025bb44(DAT_803dcd90,0,0,0,1,0);
    FUN_8025bc04(DAT_803dcd90,0,0,0,1,0);
    DAT_803dcd30 = 1;
    FUN_8025be20(DAT_803dcd90,DAT_803dcd70);
    DAT_803dcd88 = DAT_803dcd88 + 1;
    DAT_803dcd90 = DAT_803dcd90 + 1;
    DAT_803dcd8c = DAT_803dcd8c + 1;
    DAT_803dcd80 = DAT_803dcd80 + 3;
    DAT_803dcd6a = DAT_803dcd6a + '\x01';
    DAT_803dcd69 = DAT_803dcd69 + '\x01';
  }
  else {
    FUN_8006cabc(&local_f8,&local_fc);
    local_fc = local_fc * FLOAT_803deae0;
    local_f8 = local_f8 * FLOAT_803deb08;
    FUN_8025b284(2,&local_ec,0xfffffffe);
    FUN_8025b5b8(DAT_803dcd7c,DAT_803dcd88 + 1,DAT_803dcd8c + 1);
    local_74 = FLOAT_803dcd34;
    local_70 = FLOAT_803deacc;
    local_6c = FLOAT_803deacc;
    local_68 = FLOAT_803dcdd8 * FLOAT_803dcd34 + local_f8;
    local_64 = FLOAT_803deacc;
    local_60 = FLOAT_803dcd34;
    local_5c = FLOAT_803deacc;
    local_58 = FLOAT_803deacc;
    local_54 = FLOAT_803deacc;
    local_50 = FLOAT_803deacc;
    local_4c = FLOAT_803deacc;
    local_48 = FLOAT_803deac8;
    FUN_802470c8((double)FLOAT_803deb28,auStack212,0x7a);
    FUN_80246eb4(auStack212,&local_74,&local_74);
    FUN_80246eb4(&local_74,iVar2,&local_74);
    FUN_8025d160(&local_74,DAT_803dcd80 + 3,0);
    FUN_80257f10(DAT_803dcd88 + 1,0,0,0,0,DAT_803dcd80 + 3);
    FUN_8025b1e8(DAT_803dcd90,DAT_803dcd7c,0,2,2,6,6,0,0,0);
    FUN_8025b3e4(DAT_803dcd7c,0,0);
    FUN_8025b5b8(DAT_803dcd7c + 1,DAT_803dcd88 + 2,DAT_803dcd8c + 1);
    local_a4 = FLOAT_803deacc;
    local_a0 = FLOAT_803deacc;
    local_9c = FLOAT_803dcd34;
    local_98 = FLOAT_803dcddc * FLOAT_803dcd34 + local_fc;
    local_94 = FLOAT_803deacc;
    local_90 = FLOAT_803dcd34;
    local_8c = FLOAT_803deacc;
    local_88 = FLOAT_803deacc;
    local_84 = FLOAT_803deacc;
    local_80 = FLOAT_803deacc;
    local_7c = FLOAT_803deacc;
    local_78 = FLOAT_803deac8;
    FUN_802470c8((double)FLOAT_803deb2c,auStack212,0x78);
    FUN_80246eb4(auStack212,&local_a4,&local_a4);
    FUN_80246eb4(&local_a4,iVar2,&local_a4);
    FUN_8025d160(&local_a4,DAT_803dcd80 + 6,0);
    FUN_80257f10(DAT_803dcd88 + 2,0,0,0,0,DAT_803dcd80 + 6);
    FUN_8025b1e8(DAT_803dcd90 + 1,DAT_803dcd7c + 1,0,2,2,0,0,1,0,0);
    FUN_8025b3e4(DAT_803dcd7c + 1,0,0);
    FUN_8025c0c4(DAT_803dcd90,0xff,0xff,0xff);
    FUN_8025ba40(DAT_803dcd90,0xf,0xf,0xf,0);
    FUN_8025bac0(DAT_803dcd90,7,7,7,0);
    FUN_8025bef8(DAT_803dcd90,0,0);
    FUN_8025bb44(DAT_803dcd90,0,0,0,1,0);
    FUN_8025bc04(DAT_803dcd90,0,0,0,1,0);
    DAT_803dcd30 = 1;
    FUN_8025c0c4(DAT_803dcd90 + 1,DAT_803dcd88,DAT_803dcd8c,0xff);
    FUN_8025ba40(DAT_803dcd90 + 1,0,0xe,9,0xf);
    FUN_8025bac0(DAT_803dcd90 + 1,7,7,7,0);
    FUN_8025bef8(DAT_803dcd90 + 1,0,0);
    FUN_8025bb44(DAT_803dcd90 + 1,0,0,0,1,0);
    FUN_8025bc04(DAT_803dcd90 + 1,0,0,0,1,0);
    FUN_8006c5e4(&local_f4);
    if (local_f4 != 0) {
      if (*(char *)(local_f4 + 0x48) == '\0') {
        FUN_8025a8f0(local_f4 + 0x20,DAT_803dcd8c + 1);
      }
      else {
        FUN_8025a748(local_f4 + 0x20,*(undefined4 *)(local_f4 + 0x40));
      }
    }
    FUN_8025be20(DAT_803dcd90 + 1,DAT_803dcd70);
    DAT_803dcd88 = DAT_803dcd88 + 3;
    DAT_803dcd90 = DAT_803dcd90 + 2;
    DAT_803dcd8c = DAT_803dcd8c + 2;
    DAT_803dcd80 = DAT_803dcd80 + 9;
    DAT_803dcd7c = DAT_803dcd7c + 2;
    DAT_803dcd6a = DAT_803dcd6a + '\x02';
    DAT_803dcd69 = DAT_803dcd69 + '\x03';
    DAT_803dcd68 = DAT_803dcd68 + '\x02';
  }
  DAT_803dcd6c = DAT_803dcd6c + 1;
  DAT_803dcd70 = DAT_803dcd70 + 1;
  DAT_803dcd74 = DAT_803dcd74 + 1;
  return;
}

