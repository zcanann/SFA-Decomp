// Function: FUN_8022ec10
// Entry: 8022ec10
// Size: 180 bytes

void FUN_8022ec10(double param_1,ushort *param_2)

{
  int iVar1;
  ushort local_68;
  ushort local_66;
  undefined2 local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  float afStack_50 [18];
  
  iVar1 = *(int *)(param_2 + 0x5c);
  *(float *)(iVar1 + 8) = (float)param_1;
  local_5c = FLOAT_803e7ca0;
  local_58 = FLOAT_803e7ca0;
  local_54 = FLOAT_803e7ca0;
  local_68 = *param_2;
  local_66 = param_2[1];
  local_64 = 0;
  local_60 = FLOAT_803e7cb4;
  FUN_80021fac(afStack_50,&local_68);
  FUN_80022790((double)FLOAT_803e7ca0,(double)FLOAT_803e7ca0,(double)*(float *)(iVar1 + 8),
               afStack_50,(float *)(param_2 + 0x12),(float *)(param_2 + 0x14),
               (float *)(param_2 + 0x16));
  *param_2 = *param_2 + 0x8000;
  param_2[1] = -param_2[1];
  return;
}

