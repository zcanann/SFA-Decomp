// Function: FUN_80211e6c
// Entry: 80211e6c
// Size: 196 bytes

void FUN_80211e6c(int param_1)

{
  float *pfVar1;
  
  pfVar1 = *(float **)(param_1 + 0xb8);
  FUN_8005cef0(0);
  FUN_800200e8(0x572,0);
  FUN_800200e8(0x56e,1);
  FUN_800200e8(0x566,1);
  FUN_800200e8(0x569,1);
  *pfVar1 = FLOAT_803e67a8;
  FUN_800200e8(0x55a,1);
  FUN_800200e8(0x54a,2);
  FUN_800200e8(0x54e,2);
  FUN_800200e8(0x552,1);
  FUN_800200e8(0x556,1);
  *(undefined4 *)(param_1 + 0xf4) = 0;
  FUN_800200e8(0xefd,1);
  return;
}

