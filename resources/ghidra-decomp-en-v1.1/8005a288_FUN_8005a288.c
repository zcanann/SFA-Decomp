// Function: FUN_8005a288
// Entry: 8005a288
// Size: 136 bytes

undefined4 FUN_8005a288(double param_1,float *param_2)

{
  uint uVar1;
  byte bVar2;
  
  bVar2 = 0;
  while( true ) {
    if (4 < bVar2) {
      return 1;
    }
    uVar1 = (uint)bVar2;
    if ((float)(param_1 +
               (double)((float)(&DAT_803885a8)[uVar1 * 5] +
                       (float)(&DAT_803885a4)[uVar1 * 5] * (param_2[2] - FLOAT_803dda5c) +
                       param_2[1] * (float)(&DAT_803885a0)[uVar1 * 5] +
                       (float)(&DAT_8038859c)[uVar1 * 5] * (*param_2 - FLOAT_803dda58))) <
        FLOAT_803df84c) break;
    bVar2 = bVar2 + 1;
  }
  return 0;
}

