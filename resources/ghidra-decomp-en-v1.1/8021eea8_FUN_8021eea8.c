// Function: FUN_8021eea8
// Entry: 8021eea8
// Size: 168 bytes

void FUN_8021eea8(undefined4 param_1,float *param_2,float *param_3,float *param_4)

{
  ushort *puVar1;
  ushort local_68;
  ushort local_66;
  ushort local_64;
  float local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  float afStack_50 [17];
  
  puVar1 = (ushort *)FUN_8002bac4();
  local_5c = *(undefined4 *)(puVar1 + 6);
  local_58 = *(undefined4 *)(puVar1 + 8);
  local_54 = *(undefined4 *)(puVar1 + 10);
  local_68 = *puVar1;
  local_66 = puVar1[1];
  local_64 = puVar1[2];
  local_60 = FLOAT_803e7750;
  FUN_80021fac(afStack_50,&local_68);
  FUN_80022790((double)FLOAT_803e7740,(double)FLOAT_803e77d0,(double)FLOAT_803e77d4,afStack_50,
               param_2,param_3,param_4);
  return;
}

