// Function: FUN_8004f6d8
// Entry: 8004f6d8
// Size: 856 bytes

void FUN_8004f6d8(double param_1,undefined4 *param_2,float *param_3)

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
  
  if (((DAT_803dcd74 < 4) && (DAT_803dcd6a < 0xc)) && (DAT_803dcd69 < 7)) {
    dVar1 = (double)FLOAT_803deadc;
    local_6c = (float)(dVar1 / param_1);
    dVar2 = (double)local_6c;
    local_3c = FLOAT_803deacc;
    local_38 = FLOAT_803deacc;
    local_34 = (float)(-(double)*param_3 * dVar2 + dVar1);
    local_30 = FLOAT_803deacc;
    local_2c = FLOAT_803deacc;
    local_24 = (float)(-(double)param_3[2] * dVar2 + dVar1);
    local_20 = FLOAT_803deacc;
    local_1c = FLOAT_803deacc;
    local_18 = FLOAT_803deacc;
    local_14 = FLOAT_803deac8;
    local_70 = FLOAT_803deacc;
    local_68 = FLOAT_803deacc;
    local_64 = (float)(-(double)param_3[1] * dVar2 + dVar1);
    local_60 = FLOAT_803deacc;
    local_5c = FLOAT_803deacc;
    local_58 = FLOAT_803deacc;
    local_54 = FLOAT_803deadc;
    local_50 = FLOAT_803deacc;
    local_4c = FLOAT_803deacc;
    local_48 = FLOAT_803deacc;
    local_44 = FLOAT_803deac8;
    local_40 = local_6c;
    local_28 = local_6c;
    FUN_8006c540(&local_74);
    FUN_8025d160(&local_40,DAT_803dcd80,0);
    FUN_80257f10(DAT_803dcd88,0,0,0,0,DAT_803dcd80);
    FUN_8025d160(&local_70,DAT_803dcd80 + 3,0);
    FUN_80257f10(DAT_803dcd88 + 1,0,0,0,0,DAT_803dcd80 + 3);
    FUN_8025b71c(DAT_803dcd90);
    FUN_8025c0c4(DAT_803dcd90,DAT_803dcd88,DAT_803dcd8c,0xff);
    local_78 = *param_2;
    FUN_8025bdac(DAT_803dcd74,&local_78);
    FUN_8025be20(DAT_803dcd90,DAT_803dcd70);
    FUN_8025ba40(DAT_803dcd90,0xf,0xe,8,0xf);
    FUN_8025bac0(DAT_803dcd90,7,7,7,0);
    FUN_8025bef8(DAT_803dcd90,0,0);
    FUN_8025bb44(DAT_803dcd90,0,0,0,1,1);
    FUN_8025bc04(DAT_803dcd90,0,0,0,1,0);
    FUN_8025b71c(DAT_803dcd90 + 1);
    FUN_8025c0c4(DAT_803dcd90 + 1,DAT_803dcd88 + 1,DAT_803dcd8c,0xff);
    FUN_8025ba40(DAT_803dcd90 + 1,0xf,2,8,0xf);
    FUN_8025bac0(DAT_803dcd90 + 1,7,7,7,0);
    FUN_8025bef8(DAT_803dcd90 + 1,0,0);
    FUN_8025bb44(DAT_803dcd90 + 1,0,0,0,1,2);
    FUN_8025bc04(DAT_803dcd90 + 1,0,0,0,1,0);
    if (local_74 != 0) {
      if (*(char *)(local_74 + 0x48) == '\0') {
        FUN_8025a8f0(local_74 + 0x20,DAT_803dcd8c);
      }
      else {
        FUN_8025a748(local_74 + 0x20,*(undefined4 *)(local_74 + 0x40));
      }
    }
    DAT_803dcd90 = DAT_803dcd90 + 2;
    DAT_803dcd88 = DAT_803dcd88 + 2;
    DAT_803dcd8c = DAT_803dcd8c + 1;
    DAT_803dcd74 = DAT_803dcd74 + 1;
    DAT_803dcd70 = DAT_803dcd70 + 1;
    DAT_803dcd6c = DAT_803dcd6c + 1;
    DAT_803dcd80 = DAT_803dcd80 + 6;
    DAT_803dcd69 = DAT_803dcd69 + 2;
    DAT_803dcd6a = DAT_803dcd6a + 2;
  }
  return;
}

