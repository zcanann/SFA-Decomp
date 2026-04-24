// Function: FUN_8001dd88
// Entry: 8001dd88
// Size: 196 bytes

void FUN_8001dd88(double param_1,double param_2,double param_3,int *param_4)

{
  undefined4 uVar1;
  float local_18;
  int local_14;
  float local_10;
  
  if (*param_4 == 0) {
    param_4[4] = (int)(float)param_1;
    param_4[5] = (int)(float)param_2;
    param_4[6] = (int)(float)param_3;
  }
  else {
    param_4[1] = (int)(float)param_1;
    param_4[2] = (int)(float)param_2;
    param_4[3] = (int)(float)param_3;
    FUN_8002b1e8(*param_4,param_4 + 1,param_4 + 4,1);
  }
  uVar1 = FUN_8000f54c();
  if (param_4[0x18] == 0) {
    local_18 = (float)param_4[4] - FLOAT_803dcdd8;
    local_14 = param_4[5];
    local_10 = (float)param_4[6] - FLOAT_803dcddc;
    FUN_80247494(uVar1,&local_18,param_4 + 7);
  }
  else {
    param_4[7] = param_4[4];
    param_4[8] = param_4[5];
    param_4[9] = param_4[6];
  }
  return;
}

