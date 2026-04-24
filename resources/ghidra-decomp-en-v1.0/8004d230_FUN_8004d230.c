// Function: FUN_8004d230
// Entry: 8004d230
// Size: 900 bytes

void FUN_8004d230(void)

{
  int iVar1;
  double dVar2;
  double dVar3;
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
  undefined auStack72 [68];
  
  iVar1 = FUN_8006c754();
  dVar3 = (double)FLOAT_803deadc;
  FUN_8024740c((double)FLOAT_803deaf4,(double)FLOAT_803deaf8,(double)FLOAT_803deaf8,
               (double)FLOAT_803deaf4,dVar3,dVar3,dVar3,dVar3,auStack72);
  FUN_8025d160(auStack72,DAT_803dcd80,0);
  FUN_80257f10(DAT_803dcd88,0,0,0,0,DAT_803dcd80);
  FUN_8025b71c(DAT_803dcd90);
  FUN_8025c0c4(DAT_803dcd90,DAT_803dcd88,DAT_803dcd8c,0xff);
  FUN_8025bf50(1,0,0,0,1);
  FUN_8025bef8(DAT_803dcd90,1,1);
  if (DAT_803dcd90 == 0) {
    FUN_8025ba40(0,0xf,0xf,0xf,0xf);
  }
  else {
    FUN_8025ba40(DAT_803dcd90,0xf,0xf,0xf,0);
  }
  FUN_8025bac0(DAT_803dcd90,7,7,7,4);
  FUN_8025bb44(DAT_803dcd90,0,0,0,1,0);
  FUN_8025bc04(DAT_803dcd90,0,0,0,1,2);
  DAT_803dcd30 = 1;
  if (iVar1 != 0) {
    if (*(char *)(iVar1 + 0x48) == '\0') {
      FUN_8025a8f0(iVar1 + 0x20,DAT_803dcd8c);
    }
    else {
      FUN_8025a748(iVar1 + 0x20,*(undefined4 *)(iVar1 + 0x40));
    }
  }
  DAT_803dcd80 = DAT_803dcd80 + 3;
  DAT_803dcd88 = DAT_803dcd88 + 1;
  DAT_803dcd90 = DAT_803dcd90 + 1;
  DAT_803dcd8c = DAT_803dcd8c + 1;
  iVar1 = FUN_8002b9ec();
  if (iVar1 == 0) {
    dVar3 = (double)FLOAT_803deafc;
  }
  else {
    dVar3 = (double)FUN_8000f480((double)*(float *)(iVar1 + 0x18),(double)*(float *)(iVar1 + 0x1c),
                                 (double)*(float *)(iVar1 + 0x20));
  }
  dVar2 = -(double)(FLOAT_803deac8 /
                   (float)(dVar3 - (double)(float)(dVar3 - (double)FLOAT_803deb00)));
  local_78 = FLOAT_803deacc;
  local_74 = FLOAT_803deacc;
  local_70 = (float)dVar2;
  local_6c = (float)(dVar2 * (double)(float)(dVar3 - (double)FLOAT_803deb00));
  local_68 = FLOAT_803deacc;
  local_64 = FLOAT_803deacc;
  local_60 = FLOAT_803deacc;
  local_5c = FLOAT_803deacc;
  local_58 = FLOAT_803deacc;
  local_54 = FLOAT_803deacc;
  local_50 = FLOAT_803deacc;
  local_4c = FLOAT_803deacc;
  FUN_8025d160(&local_78,DAT_803dcd80,0);
  FUN_80257f10(DAT_803dcd88,0,0,0,0,DAT_803dcd80);
  FUN_8025b71c(DAT_803dcd90);
  FUN_8025c0c4(DAT_803dcd90,DAT_803dcd88,DAT_803dcd8c,0xff);
  FUN_8025bef8(DAT_803dcd90,1,1);
  FUN_8025ba40(DAT_803dcd90,0xf,0xf,0xf,0);
  FUN_8025be8c(DAT_803dcd90,0);
  FUN_8025bac0(DAT_803dcd90,7,2,4,6);
  FUN_8025bb44(DAT_803dcd90,0,0,0,1,0);
  FUN_8025bc04(DAT_803dcd90,1,0,0,1,0);
  DAT_803dcd30 = 1;
  iVar1 = FUN_8006c74c();
  if (iVar1 != 0) {
    if (*(char *)(iVar1 + 0x48) == '\0') {
      FUN_8025a8f0(iVar1 + 0x20,DAT_803dcd8c);
    }
    else {
      FUN_8025a748(iVar1 + 0x20,*(undefined4 *)(iVar1 + 0x40));
    }
  }
  DAT_803dcd69 = DAT_803dcd69 + '\x02';
  DAT_803dcd6a = DAT_803dcd6a + '\x02';
  DAT_803dcd6b = 1;
  DAT_803dcd80 = DAT_803dcd80 + 3;
  DAT_803dcd88 = DAT_803dcd88 + 1;
  DAT_803dcd8c = DAT_803dcd8c + 1;
  DAT_803dcd90 = DAT_803dcd90 + 1;
  return;
}

