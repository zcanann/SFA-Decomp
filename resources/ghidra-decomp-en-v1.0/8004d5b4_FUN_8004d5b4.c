// Function: FUN_8004d5b4
// Entry: 8004d5b4
// Size: 292 bytes

/* WARNING: Could not reconcile some variable overlaps */

void FUN_8004d5b4(int param_1)

{
  undefined uVar1;
  undefined4 local_8;
  undefined4 local_4;
  
  uVar1 = *(undefined *)(param_1 + 0x43);
  local_4 = CONCAT13(uVar1,CONCAT12(uVar1,CONCAT11(uVar1,(undefined)local_4)));
  local_8 = local_4;
  FUN_8025bdac(DAT_803dcd74,&local_8);
  FUN_8025be20(DAT_803dcd90,DAT_803dcd70);
  FUN_8025b71c(DAT_803dcd90);
  FUN_8025c0c4(DAT_803dcd90,0xff,0xff,0xff);
  FUN_8025bef8(DAT_803dcd90,0,0);
  FUN_8025ba40(DAT_803dcd90,0,2,0xe,0xf);
  FUN_8025bac0(DAT_803dcd90,7,7,7,0);
  FUN_8025bb44(DAT_803dcd90,0,0,0,1,0);
  FUN_8025bc04(DAT_803dcd90,0,0,0,1,0);
  DAT_803dcd30 = 1;
  DAT_803dcd6a = DAT_803dcd6a + '\x01';
  DAT_803dcd6c = DAT_803dcd6c + 1;
  DAT_803dcd70 = DAT_803dcd70 + 1;
  DAT_803dcd74 = DAT_803dcd74 + 1;
  DAT_803dcd90 = DAT_803dcd90 + 1;
  return;
}

