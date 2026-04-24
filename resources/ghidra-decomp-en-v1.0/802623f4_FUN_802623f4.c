// Function: FUN_802623f4
// Entry: 802623f4
// Size: 156 bytes

void FUN_802623f4(int param_1,undefined4 param_2)

{
  undefined4 uVar1;
  
  uVar1 = FUN_8024377c();
  if ((&DAT_803af1e0)[param_1 * 0x44] != 0) {
    FUN_802538e4(param_1,0);
    FUN_80253d14(param_1);
    FUN_80241044(&DAT_803af2c0 + param_1 * 0x110);
    (&DAT_803af1e0)[param_1 * 0x44] = 0;
    (&DAT_803af1e4)[param_1 * 0x44] = param_2;
    (&DAT_803af204)[param_1 * 0x44] = 0;
  }
  FUN_802437a4(uVar1);
  return;
}

