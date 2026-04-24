// Function: FUN_8004ef9c
// Entry: 8004ef9c
// Size: 228 bytes

void FUN_8004ef9c(undefined4 *param_1)

{
  undefined4 local_8 [2];
  
  local_8[0] = *param_1;
  FUN_8025bcc4(2,local_8);
  FUN_8025b71c(DAT_803dcd90);
  FUN_8025c0c4(DAT_803dcd90,0xff,0xff,0xff);
  FUN_8025ba40(DAT_803dcd90,0xf,0,4,0xf);
  FUN_8025bac0(DAT_803dcd90,7,7,7,0);
  FUN_8025bef8(DAT_803dcd90,0,0);
  FUN_8025bb44(DAT_803dcd90,0,0,0,1,0);
  FUN_8025bc04(DAT_803dcd90,0,0,0,1,0);
  DAT_803dcd30 = 1;
  DAT_803dcd6a = DAT_803dcd6a + '\x01';
  DAT_803dcd90 = DAT_803dcd90 + 1;
  return;
}

