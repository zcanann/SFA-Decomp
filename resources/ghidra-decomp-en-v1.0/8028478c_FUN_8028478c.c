// Function: FUN_8028478c
// Entry: 8028478c
// Size: 204 bytes

bool FUN_8028478c(undefined4 param_1,undefined4 param_2,undefined4 *param_3)

{
  bool bVar1;
  
  DAT_803de3a4 = FUN_80284b6c(0xa00);
  bVar1 = DAT_803de3a4 != 0;
  if (bVar1) {
    FUN_800033a8(DAT_803de3a4,0,0xa00);
    FUN_802419e8(DAT_803de3a4,0xa00);
    DAT_803de3ac = 0;
    DAT_803de3a8 = 1;
    DAT_803de3c4 = 1;
    DAT_803de3b0 = 0;
    DAT_803de3a0 = param_1;
    FUN_8024f6b8(&LAB_80284670);
    FUN_8024f6fc(DAT_803de3a4 + -0x80000000 + (uint)DAT_803de3c4 * 0x280,0x280);
    DAT_803bd154 = 0x20;
    *param_3 = 32000;
  }
  return bVar1;
}

