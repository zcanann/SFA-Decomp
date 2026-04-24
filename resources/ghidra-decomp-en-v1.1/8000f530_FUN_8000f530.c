// Function: FUN_8000f530
// Entry: 8000f530
// Size: 36 bytes

void FUN_8000f530(double param_1,double param_2,double param_3)

{
  uint uVar1;
  
  uVar1 = (uint)DAT_803dd50d;
  (&DAT_80338e3c)[uVar1 * 0x18] = (float)param_1;
  (&DAT_80338e40)[uVar1 * 0x18] = (float)param_2;
  (&DAT_80338e44)[uVar1 * 0x18] = (float)param_3;
  return;
}

