// Function: FUN_8021bb64
// Entry: 8021bb64
// Size: 192 bytes

void FUN_8021bb64(ushort *param_1,float *param_2,float *param_3,float *param_4)

{
  ushort *puVar1;
  ushort local_68;
  ushort local_66;
  ushort local_64;
  float local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  float afStack_50 [16];
  
  puVar1 = (ushort *)FUN_8002bac4();
  if (puVar1 == (ushort *)0x0) {
    puVar1 = param_1;
  }
  local_5c = *(undefined4 *)(puVar1 + 6);
  local_58 = *(undefined4 *)(puVar1 + 8);
  local_54 = *(undefined4 *)(puVar1 + 10);
  local_68 = *puVar1;
  local_66 = puVar1[1];
  local_64 = puVar1[2];
  local_60 = FLOAT_803e76e0;
  FUN_80021fac(afStack_50,&local_68);
  FUN_80022790((double)FLOAT_803e76d4,(double)FLOAT_803dcf68,(double)FLOAT_803dcf6c,afStack_50,
               param_2,param_3,param_4);
  return;
}

