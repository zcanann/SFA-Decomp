// Function: FUN_8001dc90
// Entry: 8001dc90
// Size: 176 bytes

void FUN_8001dc90(double param_1,double param_2,double param_3,int *param_4)

{
  undefined4 uVar1;
  
  if (*param_4 == 0) {
    param_4[0xd] = (int)(float)param_1;
    param_4[0xe] = (int)(float)param_2;
    param_4[0xf] = (int)(float)param_3;
    FUN_80292c30(param_4 + 0xd,param_4 + 0xd);
  }
  else {
    param_4[10] = (int)(float)param_1;
    param_4[0xb] = (int)(float)param_2;
    param_4[0xc] = (int)(float)param_3;
    FUN_80292c30(param_4 + 10,param_4 + 10);
    FUN_8002b198(*param_4,param_4 + 10,param_4 + 0xd);
  }
  uVar1 = FUN_8000f54c();
  if (param_4[0x18] == 0) {
    FUN_80247574(uVar1,param_4 + 0xd,param_4 + 0x10);
  }
  else {
    param_4[0x10] = param_4[0xd];
    param_4[0x11] = param_4[0xe];
    param_4[0x12] = param_4[0xf];
  }
  return;
}

