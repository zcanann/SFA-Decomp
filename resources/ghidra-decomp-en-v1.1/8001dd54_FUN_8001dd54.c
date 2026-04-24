// Function: FUN_8001dd54
// Entry: 8001dd54
// Size: 176 bytes

void FUN_8001dd54(double param_1,double param_2,double param_3,int *param_4)

{
  float *pfVar1;
  
  if (*param_4 == 0) {
    param_4[0xd] = (int)(float)param_1;
    param_4[0xe] = (int)(float)param_2;
    param_4[0xf] = (int)(float)param_3;
    FUN_80293390((float *)(param_4 + 0xd),(float *)(param_4 + 0xd));
  }
  else {
    param_4[10] = (int)(float)param_1;
    param_4[0xb] = (int)(float)param_2;
    param_4[0xc] = (int)(float)param_3;
    FUN_80293390((float *)(param_4 + 10),(float *)(param_4 + 10));
    FUN_8002b270((ushort *)*param_4,(float *)(param_4 + 10),(float *)(param_4 + 0xd));
  }
  pfVar1 = (float *)FUN_8000f56c();
  if (param_4[0x18] == 0) {
    FUN_80247cd8(pfVar1,(float *)(param_4 + 0xd),(float *)(param_4 + 0x10));
  }
  else {
    param_4[0x10] = param_4[0xd];
    param_4[0x11] = param_4[0xe];
    param_4[0x12] = param_4[0xf];
  }
  return;
}

