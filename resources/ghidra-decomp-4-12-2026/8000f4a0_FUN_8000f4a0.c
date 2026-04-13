// Function: FUN_8000f4a0
// Entry: 8000f4a0
// Size: 96 bytes

void FUN_8000f4a0(double param_1,double param_2,double param_3)

{
  uint uVar1;
  
  uVar1 = (uint)DAT_803dd50d;
  FUN_80293900((double)((float)(param_3 - (double)(float)(&DAT_80338e44)[uVar1 * 0x18]) *
                        (float)(param_3 - (double)(float)(&DAT_80338e44)[uVar1 * 0x18]) +
                       (float)(param_1 - (double)(float)(&DAT_80338e3c)[uVar1 * 0x18]) *
                       (float)(param_1 - (double)(float)(&DAT_80338e3c)[uVar1 * 0x18]) +
                       (float)(param_2 - (double)(float)(&DAT_80338e40)[uVar1 * 0x18]) *
                       (float)(param_2 - (double)(float)(&DAT_80338e40)[uVar1 * 0x18])));
  return;
}

