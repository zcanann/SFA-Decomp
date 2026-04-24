// Function: FUN_8001d994
// Entry: 8001d994
// Size: 76 bytes

void FUN_8001d994(double param_1,double param_2,int param_3)

{
  double dVar1;
  double dVar2;
  
  *(float *)(param_3 + 0x10c) = (float)param_1;
  *(float *)(param_3 + 0x110) = (float)param_2;
  dVar2 = (double)(*(float *)(param_3 + 0x10c) * FLOAT_803de790);
  dVar1 = (double)FLOAT_803de75c;
  FUN_80259670(dVar1,dVar1,(double)FLOAT_803de760,dVar2,dVar1,
               (double)(float)((double)FLOAT_803de760 - dVar2),param_3 + 0xc0);
  return;
}

