// Function: FUN_80097228
// Entry: 80097228
// Size: 212 bytes

void FUN_80097228(undefined4 *param_1,uint param_2,uint param_3,uint param_4,uint param_5)

{
  int *piVar1;
  uint local_38;
  uint local_34;
  uint local_30;
  uint local_2c;
  undefined2 local_28;
  undefined2 local_26;
  undefined2 local_24;
  float local_20;
  undefined4 local_1c;
  undefined4 local_18;
  undefined4 local_14;
  
  local_20 = FLOAT_803dffd4;
  local_24 = 0;
  local_26 = 0;
  local_28 = 0;
  local_1c = *param_1;
  local_18 = param_1[1];
  local_14 = param_1[2];
  piVar1 = (int *)FUN_80013ee8(0x5a);
  local_38 = param_2 & 0xff;
  local_34 = param_3 & 0xff;
  local_30 = param_4 & 0xff;
  local_2c = param_5 & 0xff;
  (**(code **)(*piVar1 + 4))(0,1,&local_28,0x401,0xffffffff,&local_38);
  return;
}

