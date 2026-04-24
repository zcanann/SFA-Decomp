// Function: FUN_802bb780
// Entry: 802bb780
// Size: 164 bytes

void FUN_802bb780(ushort *param_1,float *param_2,float *param_3,float *param_4)

{
  ushort local_68;
  ushort local_66;
  ushort local_64;
  float local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  float afStack_50 [17];
  
  local_5c = *(undefined4 *)(param_1 + 6);
  local_58 = *(undefined4 *)(param_1 + 8);
  local_54 = *(undefined4 *)(param_1 + 10);
  local_68 = *param_1;
  local_66 = param_1[1];
  local_64 = param_1[2];
  local_60 = FLOAT_803e8ef0;
  FUN_80021fac(afStack_50,&local_68);
  FUN_80022790((double)FLOAT_803e8ecc,(double)FLOAT_803e8f30,(double)FLOAT_803e8f34,afStack_50,
               param_2,param_3,param_4);
  return;
}

