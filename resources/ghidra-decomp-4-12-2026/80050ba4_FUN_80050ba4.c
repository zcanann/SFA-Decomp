// Function: FUN_80050ba4
// Entry: 80050ba4
// Size: 176 bytes

void FUN_80050ba4(uint param_1)

{
  float afStack_48 [11];
  float local_1c;
  undefined4 local_18;
  uint uStack_14;
  undefined4 local_10;
  uint uStack_c;
  
  uStack_14 = param_1 ^ 0x80000000;
  local_18 = 0x43300000;
  local_10 = 0x43300000;
  uStack_c = uStack_14;
  FUN_80247a7c((double)(float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803df7b0),
               (double)(float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803df7b0),
               (double)FLOAT_803df74c,afStack_48);
  local_1c = FLOAT_803df748;
  FUN_8025d8c4(afStack_48,DAT_803dda00,0);
  FUN_80258674(DAT_803dda08,1,4,0x3c,0,DAT_803dda00);
  DAT_803dda00 = DAT_803dda00 + 3;
  DAT_803dda08 = DAT_803dda08 + 1;
  DAT_803dd9e9 = DAT_803dd9e9 + '\x01';
  return;
}

