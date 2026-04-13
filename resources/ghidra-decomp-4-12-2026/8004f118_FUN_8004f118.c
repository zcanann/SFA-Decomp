// Function: FUN_8004f118
// Entry: 8004f118
// Size: 228 bytes

void FUN_8004f118(undefined4 *param_1)

{
  undefined4 local_8 [2];
  
  local_8[0] = *param_1;
  FUN_8025c428(2,(byte *)local_8);
  FUN_8025be80(DAT_803dda10);
  FUN_8025c828(DAT_803dda10,0xff,0xff,0xff);
  FUN_8025c1a4(DAT_803dda10,0xf,0,4,0xf);
  FUN_8025c224(DAT_803dda10,7,7,7,0);
  FUN_8025c65c(DAT_803dda10,0,0);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  DAT_803dd9b0 = 1;
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  return;
}

