// Function: FUN_802124e4
// Entry: 802124e4
// Size: 196 bytes

void FUN_802124e4(int param_1)

{
  float *pfVar1;
  
  pfVar1 = *(float **)(param_1 + 0xb8);
  FUN_8005d06c(0);
  FUN_800201ac(0x572,0);
  FUN_800201ac(0x56e,1);
  FUN_800201ac(0x566,1);
  FUN_800201ac(0x569,1);
  *pfVar1 = FLOAT_803e7440;
  FUN_800201ac(0x55a,1);
  FUN_800201ac(0x54a,2);
  FUN_800201ac(0x54e,2);
  FUN_800201ac(0x552,1);
  FUN_800201ac(0x556,1);
  *(undefined4 *)(param_1 + 0xf4) = 0;
  FUN_800201ac(0xefd,1);
  return;
}

