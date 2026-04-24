// Function: FUN_8005de94
// Entry: 8005de94
// Size: 200 bytes

void FUN_8005de94(undefined4 param_1,undefined4 param_2,int param_3)

{
  uint uVar1;
  
  if (DAT_803dce30 == 1000) {
    FUN_8005db38();
    DAT_803dce30 = 0;
  }
  uVar1 = (uint)-*(float *)(param_3 + 8);
  if ((int)uVar1 < 0) {
    uVar1 = 0;
  }
  else if (0x7ffffff < (int)uVar1) {
    uVar1 = 0x7ffffff;
  }
  (&DAT_8037e0c0)[DAT_803dce30 * 4] = param_1;
  (&DAT_8037e0c4)[DAT_803dce30 * 4] = param_2;
  (&DAT_8037e0c8)[DAT_803dce30 * 4] = uVar1 | 0x38000000;
  (&DAT_8037e0cc)[DAT_803dce30 * 4] = 7;
  DAT_803dce30 = DAT_803dce30 + 1;
  return;
}

