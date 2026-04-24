// Function: FUN_8004ce0c
// Entry: 8004ce0c
// Size: 1060 bytes

void FUN_8004ce0c(undefined4 param_1)

{
  int local_80;
  int local_7c;
  float local_78;
  float local_74;
  float local_70 [5];
  float local_5c;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  
  FUN_80257f10(0,1,4,0x3c,0,0x7d);
  FUN_8025b71c(0);
  FUN_8025c0c4(0,0,0,4);
  FUN_8025ba40(0,0xf,8,10,0xf);
  FUN_8025bac0(0,4,7,5,7);
  FUN_8025bef8(0,0,0);
  FUN_8025bb44(0,0,0,0,1,0);
  FUN_8025bc04(0,0,0,0,1,0);
  DAT_803dcd30 = 1;
  local_40 = FLOAT_803deae4;
  local_3c = FLOAT_803deacc;
  local_38 = FLOAT_803deacc;
  local_34 = FLOAT_803deacc;
  local_30 = FLOAT_803deacc;
  local_2c = FLOAT_803deacc;
  local_28 = FLOAT_803deae4;
  local_24 = FLOAT_803deacc;
  FUN_8025d160(&local_40,0x1e,1);
  FUN_80257f10(1,1,0,0x1e,0,0x7d);
  FUN_8006c5e4(&local_7c);
  if (local_7c != 0) {
    if (*(char *)(local_7c + 0x48) == '\0') {
      FUN_8025a8f0(local_7c + 0x20,2);
    }
    else {
      FUN_8025a748(local_7c + 0x20,*(undefined4 *)(local_7c + 0x40),2);
    }
  }
  FUN_8006cabc(&local_74,&local_78);
  FUN_802472e4((double)(FLOAT_803deae0 * local_74),(double)(FLOAT_803deae0 * local_78),
               (double)FLOAT_803deacc,local_70);
  local_70[0] = FLOAT_803deae8;
  local_5c = FLOAT_803deae8;
  FUN_8025d160(local_70,0x21,1);
  FUN_80257f10(2,1,0,0x21,0,0x7d);
  FUN_8025b5b8(0,2,2);
  FUN_8025b3e4(0,0,0);
  FUN_8025b1e8(1,0,0,7,1,0,0,0,0,0);
  FUN_8025be20(1,4);
  FUN_8025c0c4(1,1,1,0xff);
  FUN_8025ba40(1,8,0xe,0,0);
  FUN_8025bac0(1,7,4,0,7);
  FUN_8025bef8(1,0,0);
  FUN_8025bb44(1,1,1,0,1,0);
  FUN_8025bc04(1,0,0,0,1,0);
  FUN_8006c5b8(&local_80);
  if (local_80 != 0) {
    if (*(char *)(local_80 + 0x48) == '\0') {
      FUN_8025a8f0(local_80 + 0x20,3);
    }
    else {
      FUN_8025a748(local_80 + 0x20,*(undefined4 *)(local_80 + 0x40),3);
    }
  }
  local_40 = FLOAT_803deacc;
  local_3c = FLOAT_803deacc;
  local_38 = FLOAT_803deaec;
  local_34 = FLOAT_803deaf0;
  local_30 = FLOAT_803deacc;
  local_2c = FLOAT_803deacc;
  local_28 = FLOAT_803deacc;
  local_24 = FLOAT_803deacc;
  FUN_80246eb4(&local_40,param_1,&local_40);
  FUN_8025d160(&local_40,0x24,1);
  FUN_80257f10(3,1,0,0x24,0,0x7d);
  FUN_8025b71c(2);
  FUN_8025c0c4(2,3,3,0xff);
  FUN_8025ba40(2,0xf,0xf,0xf,0);
  FUN_8025bac0(2,7,4,0,7);
  FUN_8025bef8(2,0,0);
  FUN_8025bb44(2,0,0,0,1,0);
  FUN_8025bc04(2,0,0,0,1,0);
  DAT_803dcd68 = 1;
  DAT_803dcd69 = 4;
  DAT_803dcd6a = 3;
  DAT_803dcd7c = 1;
  DAT_803dcd84 = 0x27;
  DAT_803dcd88 = 4;
  DAT_803dcd8c = 4;
  DAT_803dcd90 = 3;
  return;
}

