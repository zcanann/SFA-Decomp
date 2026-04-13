// Function: FUN_80262bf4
// Entry: 80262bf4
// Size: 172 bytes

int FUN_80262bf4(int param_1)

{
  int iVar1;
  undefined4 auStack_14 [2];
  
  iVar1 = FUN_8025f52c(param_1,auStack_14);
  if (-1 < iVar1) {
    FUN_80243e74();
    if ((&DAT_803afe40)[param_1 * 0x44] != 0) {
      FUN_80254048(param_1,0);
      FUN_80254478(param_1);
      FUN_8024173c((int *)(&DAT_803aff20 + param_1 * 0x110));
      (&DAT_803afe40)[param_1 * 0x44] = 0;
      (&DAT_803afe44)[param_1 * 0x44] = 0xfffffffd;
      (&DAT_803afe64)[param_1 * 0x44] = 0;
    }
    FUN_80243e9c();
    iVar1 = 0;
  }
  return iVar1;
}

