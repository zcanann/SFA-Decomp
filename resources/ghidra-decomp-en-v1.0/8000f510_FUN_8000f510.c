// Function: FUN_8000f510
// Entry: 8000f510
// Size: 36 bytes

void FUN_8000f510(double param_1,double param_2,double param_3)

{
  uint uVar1;
  
  uVar1 = (uint)DAT_803dc88d;
  (&DAT_803381dc)[uVar1 * 0x18] = (float)param_1;
  (&DAT_803381e0)[uVar1 * 0x18] = (float)param_2;
  (&DAT_803381e4)[uVar1 * 0x18] = (float)param_3;
  return;
}

