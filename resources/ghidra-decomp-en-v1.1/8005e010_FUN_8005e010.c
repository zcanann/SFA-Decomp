// Function: FUN_8005e010
// Entry: 8005e010
// Size: 200 bytes

void FUN_8005e010(undefined4 param_1,undefined4 param_2,int param_3)

{
  uint uVar1;
  
  if (DAT_803ddab0 == 1000) {
    FUN_8005dcb4();
    DAT_803ddab0 = 0;
  }
  uVar1 = (uint)-*(float *)(param_3 + 8);
  if ((int)uVar1 < 0) {
    uVar1 = 0;
  }
  else if (0x7ffffff < (int)uVar1) {
    uVar1 = 0x7ffffff;
  }
  (&DAT_8037ed20)[DAT_803ddab0 * 4] = param_1;
  (&DAT_8037ed24)[DAT_803ddab0 * 4] = param_2;
  (&DAT_8037ed28)[DAT_803ddab0 * 4] = uVar1 | 0x38000000;
  (&DAT_8037ed2c)[DAT_803ddab0 * 4] = 7;
  DAT_803ddab0 = DAT_803ddab0 + 1;
  return;
}

