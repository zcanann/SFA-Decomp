// Function: FUN_8000f480
// Entry: 8000f480
// Size: 96 bytes

void FUN_8000f480(double param_1,double param_2,double param_3)

{
  uint uVar1;
  
  uVar1 = (uint)DAT_803dc88d;
  FUN_802931a0((double)((float)(param_3 - (double)(float)(&DAT_803381e4)[uVar1 * 0x18]) *
                        (float)(param_3 - (double)(float)(&DAT_803381e4)[uVar1 * 0x18]) +
                       (float)(param_1 - (double)(float)(&DAT_803381dc)[uVar1 * 0x18]) *
                       (float)(param_1 - (double)(float)(&DAT_803381dc)[uVar1 * 0x18]) +
                       (float)(param_2 - (double)(float)(&DAT_803381e0)[uVar1 * 0x18]) *
                       (float)(param_2 - (double)(float)(&DAT_803381e0)[uVar1 * 0x18])));
  return;
}

