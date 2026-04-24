// Function: FUN_80052764
// Entry: 80052764
// Size: 344 bytes

void FUN_80052764(undefined4 param_1)

{
  undefined4 local_18;
  undefined4 local_14 [4];
  
  FUN_8025b71c(DAT_803dcd90);
  FUN_8004bf88(param_1,1,1,local_14,&local_18);
  FUN_8025be8c(DAT_803dcd90,local_18);
  FUN_8025be20(DAT_803dcd90,local_14[0]);
  FUN_8025c0c4(DAT_803dcd90,0xff,0xff,4);
  FUN_8025bef8(DAT_803dcd90,0,0);
  if ((DAT_803dcd6a == '\0') || (DAT_803dcd30 == '\0')) {
    FUN_8025ba40(DAT_803dcd90,0xf,0xf,0xf,0xe);
    FUN_8025bac0(DAT_803dcd90,7,7,7,6);
  }
  else {
    FUN_8025ba40(DAT_803dcd90,0xf,0,0xe,0xf);
    FUN_8025bac0(DAT_803dcd90,7,0,6,7);
  }
  FUN_8025bb44(DAT_803dcd90,0,0,0,1,0);
  FUN_8025bc04(DAT_803dcd90,0,0,0,1,0);
  DAT_803dcd30 = 1;
  DAT_803dcd6a = DAT_803dcd6a + '\x01';
  DAT_803dcd90 = DAT_803dcd90 + 1;
  return;
}

