// Function: FUN_8022ece0
// Entry: 8022ece0
// Size: 148 bytes

void FUN_8022ece0(double param_1,undefined2 *param_2)

{
  int iVar1;
  undefined2 local_68;
  undefined2 local_66;
  undefined2 local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  undefined auStack80 [72];
  
  iVar1 = *(int *)(param_2 + 0x5c);
  *(float *)(iVar1 + 4) = (float)param_1;
  local_5c = FLOAT_803e7044;
  local_58 = FLOAT_803e7044;
  local_54 = FLOAT_803e7044;
  local_68 = *param_2;
  local_66 = param_2[1];
  local_64 = 0;
  local_60 = FLOAT_803e704c;
  FUN_80021ee8(auStack80,&local_68);
  FUN_800226cc((double)FLOAT_803e7044,(double)FLOAT_803e7044,(double)*(float *)(iVar1 + 4),auStack80
               ,param_2 + 0x12,param_2 + 0x14,param_2 + 0x16);
  return;
}

