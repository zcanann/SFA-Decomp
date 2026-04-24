// Function: FUN_8027bebc
// Entry: 8027bebc
// Size: 264 bytes

void FUN_8027bebc(uint param_1,undefined param_2,undefined4 param_3)

{
  int iVar1;
  
  param_1 = param_1 & 0xff;
  iVar1 = param_1 * 0xbc;
  FUN_800033a8((&DAT_803cc208)[param_1 * 0x2f],0,0x3c00);
  FUN_80241a50((&DAT_803cc208)[param_1 * 0x2f],0x3c00);
  FUN_800033a8((&DAT_803cc1e0)[param_1 * 0x2f],0,0x36);
  (&DAT_803cc1ec)[param_1 * 0x2f] = 0;
  (&DAT_803cc1e8)[param_1 * 0x2f] = 0;
  (&DAT_803cc1e4)[param_1 * 0x2f] = 0;
  (&DAT_803cc1f8)[param_1 * 0x2f] = 0;
  (&DAT_803cc1f4)[param_1 * 0x2f] = 0;
  (&DAT_803cc1f0)[param_1 * 0x2f] = 0;
  (&DAT_803cc204)[param_1 * 0x2f] = 0;
  (&DAT_803cc200)[param_1 * 0x2f] = 0;
  (&DAT_803cc1fc)[param_1 * 0x2f] = 0;
  FUN_80241a50((&DAT_803cc1e0)[param_1 * 0x2f],0x36);
  FUN_800033a8((&DAT_803cc210)[param_1 * 0x2f],0,0x780);
  FUN_80241a50((&DAT_803cc210)[param_1 * 0x2f],0x780);
  FUN_800033a8((&DAT_803cc21c)[param_1 * 0x2f],0,0x780);
  FUN_80241a50((&DAT_803cc21c)[param_1 * 0x2f],0x780);
  (&DAT_803cc228)[param_1 * 0x2f] = 0;
  (&DAT_803cc22c)[param_1 * 0x2f] = 0;
  (&DAT_803cc230)[iVar1] = 1;
  (&DAT_803cc231)[iVar1] = param_2;
  (&DAT_803cc232)[iVar1] = 0;
  (&DAT_803cc234)[param_1 * 0x2f] = param_3;
  (&DAT_803cc290)[param_1 * 0x2f] = 0;
  (&DAT_803cc28c)[param_1 * 0x2f] = 0;
  return;
}

