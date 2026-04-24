// Function: FUN_800510f0
// Entry: 800510f0
// Size: 600 bytes

void FUN_800510f0(int param_1,char param_2,uint param_3)

{
  undefined auStack120 [48];
  undefined auStack72 [60];
  
  if (DAT_803dcd68 == '\0') {
    FUN_8025b71c(DAT_803dcd90);
  }
  if (param_2 == '\0') {
    FUN_80247318((double)FLOAT_803deb40,(double)FLOAT_803deb40,(double)FLOAT_803deacc,auStack120);
    FUN_802472e4((double)FLOAT_803deadc,(double)FLOAT_803deadc,(double)FLOAT_803deac8,auStack72);
    FUN_80246eb4(auStack72,auStack120,auStack120);
    FUN_8025d160(auStack120,DAT_803dcd80,0);
    FUN_80257f10(DAT_803dcd88,1,1,0x1e,0,DAT_803dcd80);
    FUN_8025c0c4(DAT_803dcd90,DAT_803dcd88,DAT_803dcd8c,4);
    DAT_803dcd80 = DAT_803dcd80 + 3;
    DAT_803dcd88 = DAT_803dcd88 + 1;
    DAT_803dcd69 = DAT_803dcd69 + '\x01';
  }
  else {
    FUN_8025b764(DAT_803dcd90);
    FUN_8025c0c4(DAT_803dcd90,DAT_803dcd88 + -1,DAT_803dcd8c,0xff);
  }
  FUN_8025bac0(DAT_803dcd90,7,4,3,7);
  if (param_2 == '\0') {
    FUN_8025ba40(DAT_803dcd90,0xf,8,10,0xf);
  }
  else {
    FUN_8025ba40(DAT_803dcd90,0xf,8,4,0xf);
  }
  FUN_8025bc04(DAT_803dcd90,0,0,0,1,0);
  FUN_8025bb44(DAT_803dcd90,0,0,0,1,3);
  if ((param_3 & 1) == 0) {
    FUN_8025bf50(3,0,0,0,1);
  }
  else {
    FUN_8025bf50(3,2,2,2,1);
  }
  FUN_8025bef8(DAT_803dcd90,0,3);
  if (param_1 != 0) {
    if (*(char *)(param_1 + 0x48) == '\0') {
      FUN_8025a8f0(param_1 + 0x20,DAT_803dcd8c);
    }
    else {
      FUN_8025a748(param_1 + 0x20,*(undefined4 *)(param_1 + 0x40));
    }
  }
  DAT_803dcd6a = DAT_803dcd6a + '\x01';
  DAT_803dcd8c = DAT_803dcd8c + 1;
  DAT_803dcd90 = DAT_803dcd90 + 1;
  return;
}

