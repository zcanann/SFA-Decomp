// Function: FUN_80052638
// Entry: 80052638
// Size: 300 bytes

void FUN_80052638(undefined4 *param_1)

{
  undefined4 local_18;
  undefined auStack20 [4];
  undefined4 local_10 [3];
  
  FUN_8025b71c(DAT_803dcd90);
  local_18 = *param_1;
  FUN_8025bcc4(1,&local_18);
  FUN_8004bf88(param_1,1,0,local_10,auStack20);
  FUN_8025be20(DAT_803dcd90,local_10[0]);
  FUN_8025c0c4(DAT_803dcd90,0xff,0xff,0xff);
  FUN_8025bef8(DAT_803dcd90,0,0);
  if ((DAT_803dcd6a != '\0') && (DAT_803dcd30 != '\0')) {
    FUN_8025ba40(DAT_803dcd90,0,0xe,3,0xf);
    FUN_8025bac0(DAT_803dcd90,7,7,7,0);
  }
  FUN_8025bb44(DAT_803dcd90,0,0,0,1,0);
  FUN_8025bc04(DAT_803dcd90,0,0,0,1,0);
  DAT_803dcd30 = 1;
  DAT_803dcd6a = DAT_803dcd6a + '\x01';
  DAT_803dcd90 = DAT_803dcd90 + 1;
  return;
}

