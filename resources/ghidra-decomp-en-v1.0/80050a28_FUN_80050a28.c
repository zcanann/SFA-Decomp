// Function: FUN_80050a28
// Entry: 80050a28
// Size: 176 bytes

void FUN_80050a28(uint param_1)

{
  undefined auStack72 [44];
  float local_1c;
  undefined4 local_18;
  uint uStack20;
  undefined4 local_10;
  uint uStack12;
  
  uStack20 = param_1 ^ 0x80000000;
  local_18 = 0x43300000;
  local_10 = 0x43300000;
  uStack12 = uStack20;
  FUN_80247318((double)(float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803deb30),
               (double)(float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803deb30),
               (double)FLOAT_803deacc,auStack72);
  local_1c = FLOAT_803deac8;
  FUN_8025d160(auStack72,DAT_803dcd80,0);
  FUN_80257f10(DAT_803dcd88,1,4,0x3c,0,DAT_803dcd80);
  DAT_803dcd69 = DAT_803dcd69 + '\x01';
  DAT_803dcd80 = DAT_803dcd80 + 3;
  DAT_803dcd88 = DAT_803dcd88 + 1;
  return;
}

