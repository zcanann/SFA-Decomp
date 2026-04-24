// Function: FUN_8001da58
// Entry: 8001da58
// Size: 76 bytes

void FUN_8001da58(double param_1,double param_2,int param_3)

{
  double dVar1;
  double dVar2;
  
  *(float *)(param_3 + 0x10c) = (float)param_1;
  *(float *)(param_3 + 0x110) = (float)param_2;
  dVar2 = (double)(*(float *)(param_3 + 0x10c) * FLOAT_803df410);
  dVar1 = (double)FLOAT_803df3dc;
  FUN_80259dd4(dVar1,dVar1,(double)FLOAT_803df3e0,dVar2,dVar1,
               (double)(float)((double)FLOAT_803df3e0 - dVar2),param_3 + 0xc0);
  return;
}

