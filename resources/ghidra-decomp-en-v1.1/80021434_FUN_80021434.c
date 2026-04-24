// Function: FUN_80021434
// Entry: 80021434
// Size: 96 bytes

/* WARNING: Removing unreachable block (ram,0x8002147c) */
/* WARNING: Removing unreachable block (ram,0x80021444) */

double FUN_80021434(double param_1,double param_2,double param_3)

{
  float fVar1;
  double dVar2;
  
  fVar1 = FLOAT_803df440;
  if (param_2 <= (double)FLOAT_803df444) {
    dVar2 = (double)FUN_802932a4((double)(float)((double)FLOAT_803df444 - param_2),param_3);
    fVar1 = (float)(param_1 * (double)(float)((double)FLOAT_803df444 - dVar2));
  }
  return (double)fVar1;
}

