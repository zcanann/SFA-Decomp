// Function: FUN_800f8094
// Entry: 800f8094
// Size: 436 bytes

void FUN_800f8094(int param_1,undefined2 param_2,int param_3,uint param_4)

{
  int iVar1;
  undefined4 *local_368;
  int local_364;
  float local_348;
  float local_344;
  float local_340;
  float local_33c;
  float local_338;
  float local_334;
  float local_330;
  undefined4 local_32c;
  undefined4 local_328;
  undefined2 local_324;
  undefined2 local_322;
  undefined2 local_320;
  undefined2 local_31e;
  undefined2 local_31c;
  undefined2 local_31a;
  undefined2 local_318;
  undefined2 local_316;
  uint local_314;
  undefined local_310;
  undefined local_30f;
  undefined local_30e;
  undefined local_30d;
  char local_30b;
  undefined4 local_308;
  float local_304;
  float local_300;
  float local_2fc;
  undefined *local_2f8;
  undefined2 local_2f4;
  undefined local_2f2;
  undefined auStack752 [752];
  
  local_368 = &local_308;
  local_2f2 = 0;
  local_2f4 = 8;
  local_2f8 = &DAT_803166e8;
  local_308 = 2;
  local_304 = FLOAT_803e1050;
  local_300 = FLOAT_803e1050;
  local_2fc = FLOAT_803e1050;
  local_310 = 0;
  local_33c = FLOAT_803e1054;
  local_338 = FLOAT_803e1054;
  local_334 = FLOAT_803e1054;
  local_348 = FLOAT_803e1054;
  local_344 = FLOAT_803e1054;
  local_340 = FLOAT_803e1054;
  local_330 = FLOAT_803e1058;
  local_328 = 1;
  local_32c = 0;
  local_30f = 8;
  local_30e = 0;
  local_30d = 0x10;
  iVar1 = (int)(auStack752 + -(int)local_368) / 0x18 + ((int)(auStack752 + -(int)local_368) >> 0x1f)
  ;
  local_30b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_322 = DAT_803166f8;
  local_320 = DAT_803166fa;
  local_31e = DAT_803166fc;
  local_31c = DAT_803166fe;
  local_31a = DAT_80316700;
  local_318 = DAT_80316702;
  local_316 = DAT_80316704;
  local_314 = param_4 | 0x2000492;
  if ((param_4 & 1) != 0) {
    if (param_1 == 0) {
      local_33c = FLOAT_803e1054 + *(float *)(param_3 + 0xc);
      local_338 = FLOAT_803e1054 + *(float *)(param_3 + 0x10);
      local_334 = FLOAT_803e1054 + *(float *)(param_3 + 0x14);
    }
    else {
      local_33c = FLOAT_803e1054 + *(float *)(param_1 + 0x18);
      local_338 = FLOAT_803e1054 + *(float *)(param_1 + 0x1c);
      local_334 = FLOAT_803e1054 + *(float *)(param_1 + 0x20);
    }
  }
  local_364 = param_1;
  local_324 = param_2;
  (**(code **)(*DAT_803dca7c + 8))(&local_368,0,8,&DAT_80316650,0xc,&DAT_803166a0,0x1fd,0);
  return;
}

