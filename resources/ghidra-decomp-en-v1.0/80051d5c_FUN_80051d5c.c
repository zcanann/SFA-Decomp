// Function: FUN_80051d5c
// Entry: 80051d5c
// Size: 604 bytes

void FUN_80051d5c(int param_1,int param_2,int param_3,undefined4 param_4)

{
  undefined4 local_18;
  undefined auStack20 [4];
  
  FUN_8025b71c(DAT_803dcd90);
  FUN_8025c0c4(DAT_803dcd90,DAT_803dcd88,DAT_803dcd8c,4);
  FUN_8025bef8(DAT_803dcd90,0,0);
  if (param_2 == 0) {
    FUN_80257f10(DAT_803dcd88,1,DAT_803dcd78,0x3c,0,0x7d);
  }
  else {
    FUN_8025d160(param_2,DAT_803dcd80,0);
    FUN_80257f10(DAT_803dcd88,1,DAT_803dcd78,0x3c,0,DAT_803dcd80);
    DAT_803dcd80 = DAT_803dcd80 + 3;
  }
  FUN_8004bf88(param_4,0,1,auStack20,&local_18);
  FUN_8025be8c(DAT_803dcd90,local_18);
  if (param_3 == 0) {
    FUN_8025ba40(DAT_803dcd90,0xf,8,10,0xf);
  }
  else if (param_3 == 8) {
    FUN_8025ba40(DAT_803dcd90,0xf,8,10,6);
  }
  else {
    FUN_8025ba40(DAT_803dcd90,8,0,1,0xf);
  }
  if (DAT_803dcd6b == '\0') {
    FUN_8025bac0(DAT_803dcd90,7,4,6,7);
    DAT_803dcd6b = '\x01';
  }
  else {
    FUN_8025bac0(DAT_803dcd90,7,4,0,7);
  }
  FUN_8025bb44(DAT_803dcd90,0,0,0,1,0);
  FUN_8025bc04(DAT_803dcd90,0,0,0,1,0);
  DAT_803dcd30 = 1;
  if (param_1 != 0) {
    if (*(char *)(param_1 + 0x48) == '\0') {
      FUN_8025a8f0(param_1 + 0x20,DAT_803dcd8c);
    }
    else {
      FUN_8025a748(param_1 + 0x20,*(undefined4 *)(param_1 + 0x40));
    }
  }
  DAT_803dcd69 = DAT_803dcd69 + '\x01';
  DAT_803dcd6a = DAT_803dcd6a + '\x01';
  DAT_803dcd78 = DAT_803dcd78 + 1;
  DAT_803dcd88 = DAT_803dcd88 + 1;
  DAT_803dcd8c = DAT_803dcd8c + 1;
  DAT_803dcd90 = DAT_803dcd90 + 1;
  return;
}

