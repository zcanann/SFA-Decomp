// Function: FUN_8005a10c
// Entry: 8005a10c
// Size: 136 bytes

undefined4 FUN_8005a10c(double param_1,float *param_2)

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
               (double)((float)(&DAT_80387948)[uVar1 * 5] +
                       (float)(&DAT_80387944)[uVar1 * 5] * (param_2[2] - FLOAT_803dcddc) +
                       param_2[1] * (float)(&DAT_80387940)[uVar1 * 5] +
                       (float)(&DAT_8038793c)[uVar1 * 5] * (*param_2 - FLOAT_803dcdd8))) <
        FLOAT_803debcc) break;
    bVar2 = bVar2 + 1;
  }
  return 0;
}

