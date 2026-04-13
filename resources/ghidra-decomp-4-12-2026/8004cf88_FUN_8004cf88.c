// Function: FUN_8004cf88
// Entry: 8004cf88
// Size: 1060 bytes

void FUN_8004cf88(float *param_1)

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
  
  FUN_80258674(0,1,4,0x3c,0,0x7d);
  FUN_8025be80(0);
  FUN_8025c828(0,0,0,4);
  FUN_8025c1a4(0,0xf,8,10,0xf);
  FUN_8025c224(0,4,7,5,7);
  FUN_8025c65c(0,0,0);
  FUN_8025c2a8(0,0,0,0,1,0);
  FUN_8025c368(0,0,0,0,1,0);
  DAT_803dd9b0 = 1;
  local_40 = FLOAT_803df764;
  local_3c = FLOAT_803df74c;
  local_38 = FLOAT_803df74c;
  local_34 = FLOAT_803df74c;
  local_30 = FLOAT_803df74c;
  local_2c = FLOAT_803df74c;
  local_28 = FLOAT_803df764;
  local_24 = FLOAT_803df74c;
  FUN_8025d8c4(&local_40,0x1e,1);
  FUN_80258674(1,1,0,0x1e,0,0x7d);
  FUN_8006c760(&local_7c);
  if (local_7c != 0) {
    if (*(char *)(local_7c + 0x48) == '\0') {
      FUN_8025b054((uint *)(local_7c + 0x20),2);
    }
    else {
      FUN_8025aeac((uint *)(local_7c + 0x20),*(uint **)(local_7c + 0x40),2);
    }
  }
  FUN_8006cc38(&local_74,&local_78);
  FUN_80247a48((double)(FLOAT_803df760 * local_74),(double)(FLOAT_803df760 * local_78),
               (double)FLOAT_803df74c,local_70);
  local_70[0] = FLOAT_803df768;
  local_5c = FLOAT_803df768;
  FUN_8025d8c4(local_70,0x21,1);
  FUN_80258674(2,1,0,0x21,0,0x7d);
  FUN_8025bd1c(0,2,2);
  FUN_8025bb48(0,0,0);
  FUN_8025b94c(1,0,0,7,1,0,0,0,0,0);
  FUN_8025c584(1,4);
  FUN_8025c828(1,1,1,0xff);
  FUN_8025c1a4(1,8,0xe,0,0);
  FUN_8025c224(1,7,4,0,7);
  FUN_8025c65c(1,0,0);
  FUN_8025c2a8(1,1,1,0,1,0);
  FUN_8025c368(1,0,0,0,1,0);
  FUN_8006c734(&local_80);
  if (local_80 != 0) {
    if (*(char *)(local_80 + 0x48) == '\0') {
      FUN_8025b054((uint *)(local_80 + 0x20),3);
    }
    else {
      FUN_8025aeac((uint *)(local_80 + 0x20),*(uint **)(local_80 + 0x40),3);
    }
  }
  local_40 = FLOAT_803df74c;
  local_3c = FLOAT_803df74c;
  local_38 = FLOAT_803df76c;
  local_34 = FLOAT_803df770;
  local_30 = FLOAT_803df74c;
  local_2c = FLOAT_803df74c;
  local_28 = FLOAT_803df74c;
  local_24 = FLOAT_803df74c;
  FUN_80247618(&local_40,param_1,&local_40);
  FUN_8025d8c4(&local_40,0x24,1);
  FUN_80258674(3,1,0,0x24,0,0x7d);
  FUN_8025be80(2);
  FUN_8025c828(2,3,3,0xff);
  FUN_8025c1a4(2,0xf,0xf,0xf,0);
  FUN_8025c224(2,7,4,0,7);
  FUN_8025c65c(2,0,0);
  FUN_8025c2a8(2,0,0,0,1,0);
  FUN_8025c368(2,0,0,0,1,0);
  DAT_803dda10 = 3;
  DAT_803dda08 = 4;
  DAT_803dda0c = 4;
  DAT_803dd9fc = 1;
  DAT_803dda04 = 0x27;
  DAT_803dd9ea = 3;
  DAT_803dd9e9 = 4;
  DAT_803dd9e8 = 1;
  return;
}

