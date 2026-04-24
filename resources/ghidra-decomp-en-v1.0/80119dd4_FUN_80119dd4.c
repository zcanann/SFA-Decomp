// Function: FUN_80119dd4
// Entry: 80119dd4
// Size: 472 bytes

void FUN_80119dd4(undefined4 param_1,undefined4 param_2)

{
  uint uVar1;
  uint uVar2;
  undefined auStack24 [20];
  
  FUN_8007719c((double)FLOAT_803e1d58,(double)FLOAT_803e1d5c,DAT_803a8684,param_2,0x100);
  FUN_8007719c((double)FLOAT_803e1d60,(double)FLOAT_803e1d5c,DAT_803a8688,param_2,0x100);
  FUN_80019908(0xff,0xff,0xff,param_2);
  DAT_803dd6b0 = DAT_803dd6a8;
  FUN_80015dc8(DAT_803dd6a8 + DAT_803dd6a4 * 0x24,0x41,0,0);
  FUN_8028f688(auStack24,&DAT_803dba0c,*(undefined *)(DAT_803dd6b0 + DAT_803dd6a4 * 0x24 + 4));
  FUN_80015dc8(auStack24,0x42,0,0);
  uVar1 = *(uint *)(DAT_803dd6b0 + DAT_803dd6a4 * 0x24 + 8);
  uVar2 = uVar1 % 0xe10;
  FUN_8028f688(auStack24,s__3d__02d__02d_8031a854,uVar1 / 0xe10,uVar2 / 0x3c,uVar2 % 0x3c);
  FUN_80015dc8(auStack24,0x43,0,0);
  FUN_8028f688(auStack24,&DAT_803dba14,*(undefined *)(DAT_803dd6b0 + DAT_803dd6a4 * 0x24 + 6));
  FUN_80015dc8(auStack24,0x44,0,0);
  FUN_8028f688(auStack24,&DAT_803dba14,*(undefined *)(DAT_803dd6b0 + DAT_803dd6a4 * 0x24 + 5));
  FUN_80015dc8(auStack24,0x45,0,0);
  return;
}

