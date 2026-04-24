// Function: FUN_80295b2c
// Entry: 80295b2c
// Size: 156 bytes

void FUN_80295b2c(double param_1,double param_2,double param_3,int param_4)

{
  int iVar1;
  
  iVar1 = *(int *)(param_4 + 0xb8);
  *(float *)(param_4 + 0x8c) = (float)param_1;
  *(float *)(param_4 + 0x80) = (float)param_1;
  *(float *)(param_4 + 0x18) = (float)param_1;
  *(float *)(param_4 + 0xc) = (float)param_1;
  *(float *)(param_4 + 0x90) = (float)param_2;
  *(float *)(param_4 + 0x84) = (float)param_2;
  *(float *)(param_4 + 0x1c) = (float)param_2;
  *(float *)(param_4 + 0x10) = (float)param_2;
  *(float *)(param_4 + 0x94) = (float)param_3;
  *(float *)(param_4 + 0x88) = (float)param_3;
  *(float *)(param_4 + 0x20) = (float)param_3;
  *(float *)(param_4 + 0x14) = (float)param_3;
  FUN_802ab5a4(param_4,iVar1,7);
  (**(code **)(*DAT_803dca8c + 0x14))(param_4,iVar1,1);
  *(code **)(iVar1 + 0x304) = FUN_802a514c;
  return;
}

