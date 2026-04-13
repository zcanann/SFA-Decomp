// Function: FUN_800527b4
// Entry: 800527b4
// Size: 300 bytes

void FUN_800527b4(char *param_1)

{
  undefined4 local_18;
  undefined4 uStack_14;
  int local_10 [3];
  
  FUN_8025be80(DAT_803dda10);
  local_18 = *(undefined4 *)param_1;
  FUN_8025c428(1,(byte *)&local_18);
  FUN_8004c104(param_1,'\x01','\0',local_10,&uStack_14);
  FUN_8025c584(DAT_803dda10,local_10[0]);
  FUN_8025c828(DAT_803dda10,0xff,0xff,0xff);
  FUN_8025c65c(DAT_803dda10,0,0);
  if ((DAT_803dd9ea != '\0') && (DAT_803dd9b0 != '\0')) {
    FUN_8025c1a4(DAT_803dda10,0,0xe,3,0xf);
    FUN_8025c224(DAT_803dda10,7,7,7,0);
  }
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  DAT_803dd9b0 = 1;
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  return;
}

