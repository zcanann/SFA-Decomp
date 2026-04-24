// Function: FUN_800528e0
// Entry: 800528e0
// Size: 344 bytes

void FUN_800528e0(char *param_1)

{
  int local_18;
  int local_14 [4];
  
  FUN_8025be80(DAT_803dda10);
  FUN_8004c104(param_1,'\x01','\x01',local_14,&local_18);
  FUN_8025c5f0(DAT_803dda10,local_18);
  FUN_8025c584(DAT_803dda10,local_14[0]);
  FUN_8025c828(DAT_803dda10,0xff,0xff,4);
  FUN_8025c65c(DAT_803dda10,0,0);
  if ((DAT_803dd9ea == '\0') || (DAT_803dd9b0 == '\0')) {
    FUN_8025c1a4(DAT_803dda10,0xf,0xf,0xf,0xe);
    FUN_8025c224(DAT_803dda10,7,7,7,6);
  }
  else {
    FUN_8025c1a4(DAT_803dda10,0xf,0,0xe,0xf);
    FUN_8025c224(DAT_803dda10,7,0,6,7);
  }
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  DAT_803dd9b0 = 1;
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  return;
}

