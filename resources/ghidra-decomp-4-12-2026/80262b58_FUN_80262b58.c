// Function: FUN_80262b58
// Entry: 80262b58
// Size: 156 bytes

void FUN_80262b58(int param_1,undefined4 param_2)

{
  FUN_80243e74();
  if ((&DAT_803afe40)[param_1 * 0x44] != 0) {
    FUN_80254048(param_1,0);
    FUN_80254478(param_1);
    FUN_8024173c((int *)(&DAT_803aff20 + param_1 * 0x110));
    (&DAT_803afe40)[param_1 * 0x44] = 0;
    (&DAT_803afe44)[param_1 * 0x44] = param_2;
    (&DAT_803afe64)[param_1 * 0x44] = 0;
  }
  FUN_80243e9c();
  return;
}

