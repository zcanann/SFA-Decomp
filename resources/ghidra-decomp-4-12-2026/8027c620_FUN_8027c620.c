// Function: FUN_8027c620
// Entry: 8027c620
// Size: 264 bytes

void FUN_8027c620(uint param_1,undefined param_2,undefined4 param_3)

{
  uint uVar1;
  int iVar2;
  
  uVar1 = param_1 & 0xff;
  iVar2 = uVar1 * 0xbc;
  FUN_800033a8((&DAT_803cce68)[uVar1 * 0x2f],0,0x3c00);
  FUN_80242148((&DAT_803cce68)[uVar1 * 0x2f],0x3c00);
  FUN_800033a8((&DAT_803cce40)[uVar1 * 0x2f],0,0x36);
  (&DAT_803cce4c)[uVar1 * 0x2f] = 0;
  (&DAT_803cce48)[uVar1 * 0x2f] = 0;
  (&DAT_803cce44)[uVar1 * 0x2f] = 0;
  (&DAT_803cce58)[uVar1 * 0x2f] = 0;
  (&DAT_803cce54)[uVar1 * 0x2f] = 0;
  (&DAT_803cce50)[uVar1 * 0x2f] = 0;
  (&DAT_803cce64)[uVar1 * 0x2f] = 0;
  (&DAT_803cce60)[uVar1 * 0x2f] = 0;
  (&DAT_803cce5c)[uVar1 * 0x2f] = 0;
  FUN_80242148((&DAT_803cce40)[uVar1 * 0x2f],0x36);
  FUN_800033a8((&DAT_803cce70)[uVar1 * 0x2f],0,0x780);
  FUN_80242148((&DAT_803cce70)[uVar1 * 0x2f],0x780);
  FUN_800033a8((&DAT_803cce7c)[uVar1 * 0x2f],0,0x780);
  FUN_80242148((&DAT_803cce7c)[uVar1 * 0x2f],0x780);
  (&DAT_803cce88)[uVar1 * 0x2f] = 0;
  (&DAT_803cce8c)[uVar1 * 0x2f] = 0;
  (&DAT_803cce90)[iVar2] = 1;
  (&DAT_803cce91)[iVar2] = param_2;
  (&DAT_803cce92)[iVar2] = 0;
  (&DAT_803cce94)[uVar1 * 0x2f] = param_3;
  (&DAT_803ccef0)[uVar1 * 0x2f] = 0;
  (&DAT_803cceec)[uVar1 * 0x2f] = 0;
  return;
}

