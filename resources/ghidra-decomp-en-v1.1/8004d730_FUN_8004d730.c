// Function: FUN_8004d730
// Entry: 8004d730
// Size: 292 bytes

void FUN_8004d730(int param_1)

{
  undefined uVar1;
  undefined4 local_8;
  undefined4 local_4;
  
  uVar1 = *(undefined *)(param_1 + 0x43);
  local_4 = CONCAT13(uVar1,CONCAT12(uVar1,CONCAT11(uVar1,(undefined)local_4)));
  local_8 = local_4;
  FUN_8025c510(DAT_803dd9f4,(byte *)&local_8);
  FUN_8025c584(DAT_803dda10,DAT_803dd9f0);
  FUN_8025be80(DAT_803dda10);
  FUN_8025c828(DAT_803dda10,0xff,0xff,0xff);
  FUN_8025c65c(DAT_803dda10,0,0);
  FUN_8025c1a4(DAT_803dda10,0,2,0xe,0xf);
  FUN_8025c224(DAT_803dda10,7,7,7,0);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  DAT_803dd9b0 = 1;
  DAT_803dd9f4 = DAT_803dd9f4 + 1;
  DAT_803dd9f0 = DAT_803dd9f0 + 1;
  DAT_803dd9ec = DAT_803dd9ec + 1;
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  return;
}

