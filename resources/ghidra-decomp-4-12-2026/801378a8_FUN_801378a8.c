// Function: FUN_801378a8
// Entry: 801378a8
// Size: 128 bytes

void FUN_801378a8(undefined param_1,undefined param_2,undefined param_3,undefined param_4)

{
  undefined *puVar1;
  
  DAT_803de664 = DAT_803de664 + 1;
  if (0xfa < DAT_803de664) {
    return;
  }
  puVar1 = DAT_803dc87c + 1;
  *DAT_803dc87c = 0x81;
  DAT_803dc87c = puVar1;
  puVar1 = DAT_803dc87c + 1;
  *DAT_803dc87c = param_1;
  DAT_803dc87c = puVar1;
  puVar1 = DAT_803dc87c + 1;
  *DAT_803dc87c = param_2;
  DAT_803dc87c = puVar1;
  puVar1 = DAT_803dc87c + 1;
  *DAT_803dc87c = param_3;
  DAT_803dc87c = puVar1;
  puVar1 = DAT_803dc87c + 1;
  *DAT_803dc87c = param_4;
  DAT_803dc87c = puVar1;
  puVar1 = DAT_803dc87c + 1;
  *DAT_803dc87c = 0;
  DAT_803dc87c = puVar1;
  return;
}

