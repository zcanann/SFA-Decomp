// Function: FUN_80283b38
// Entry: 80283b38
// Size: 40 bytes

void FUN_80283b38(uint param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5)

{
  param_1 = param_1 & 0xff;
  (&DAT_803cc28c)[param_1 * 0x2f] = param_2;
  (&DAT_803cc294)[param_1 * 0x2f] = param_3;
  (&DAT_803cc290)[param_1 * 0x2f] = param_4;
  (&DAT_803cc298)[param_1 * 0x2f] = param_5;
  return;
}

