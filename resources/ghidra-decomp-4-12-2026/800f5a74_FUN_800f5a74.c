// Function: FUN_800f5a74
// Entry: 800f5a74
// Size: 684 bytes

void FUN_800f5a74(int param_1,int param_2,int param_3,uint param_4)

{
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
  undefined local_30b;
  undefined4 local_308;
  float local_304;
  float local_300;
  float local_2fc;
  undefined *local_2f8;
  undefined2 local_2f4;
  undefined local_2f2;
  undefined4 local_2f0;
  float local_2ec;
  float local_2e8;
  float local_2e4;
  undefined *local_2e0;
  undefined2 local_2dc;
  undefined local_2da;
  undefined4 local_2d8;
  float local_2d4;
  float local_2d0;
  float local_2cc;
  undefined *local_2c8;
  undefined2 local_2c4;
  undefined local_2c2;
  undefined4 local_2c0;
  float local_2bc;
  float local_2b8;
  float local_2b4;
  undefined *local_2b0;
  undefined2 local_2ac;
  undefined local_2aa;
  undefined4 local_2a8;
  float local_2a4;
  float local_2a0;
  float local_29c;
  undefined *local_298;
  undefined2 local_294;
  undefined local_292;
  
  local_2f2 = 0;
  local_2f4 = 9;
  local_2f8 = &DAT_80316144;
  local_308 = 0x80;
  local_304 = FLOAT_803e1ad8;
  local_300 = FLOAT_803e1ad8;
  local_2fc = FLOAT_803e1adc;
  if (param_2 == 1) {
    local_2e8 = FLOAT_803e1ae0;
    local_2e4 = FLOAT_803e1ae4;
  }
  else {
    local_2e8 = FLOAT_803e1ae8;
    local_2e4 = FLOAT_803e1aec;
  }
  local_2da = 0;
  local_2dc = 8;
  local_2e0 = &DAT_80316158;
  local_2f0 = 2;
  local_2c2 = 1;
  local_2c4 = 8;
  local_2c8 = &DAT_80316144;
  local_2d8 = 2;
  local_2d4 = FLOAT_803e1aec;
  local_2d0 = FLOAT_803e1aec;
  local_2cc = FLOAT_803e1af0;
  local_2aa = 1;
  local_2ac = 9;
  local_2b0 = &DAT_80316144;
  local_2c0 = 0x100;
  local_2bc = FLOAT_803e1af4;
  local_2b8 = FLOAT_803e1ad8;
  local_2b4 = FLOAT_803e1ad8;
  local_292 = 1;
  local_294 = 9;
  local_298 = &DAT_80316144;
  local_2a8 = 4;
  local_2a4 = FLOAT_803e1ad8;
  local_2a0 = FLOAT_803e1ad8;
  local_29c = FLOAT_803e1ad8;
  local_324 = (undefined2)param_2;
  local_33c = FLOAT_803e1ad8;
  local_338 = FLOAT_803e1ad8;
  local_334 = FLOAT_803e1ad8;
  local_348 = FLOAT_803e1ad8;
  local_344 = FLOAT_803e1ad8;
  local_340 = FLOAT_803e1ad8;
  local_330 = FLOAT_803e1af0;
  local_328 = 1;
  local_32c = 0;
  local_30f = 9;
  local_30e = 0;
  local_30d = 0x20;
  local_30b = 5;
  local_322 = DAT_80316168;
  local_320 = DAT_8031616a;
  local_31e = DAT_8031616c;
  local_31c = DAT_8031616e;
  local_31a = DAT_80316170;
  local_318 = DAT_80316172;
  local_316 = DAT_80316174;
  local_368 = &local_308;
  local_314 = param_4 | 0x4000010;
  if ((param_4 & 1) != 0) {
    if (param_1 == 0) {
      local_33c = FLOAT_803e1ad8 + *(float *)(param_3 + 0xc);
      local_338 = FLOAT_803e1ad8 + *(float *)(param_3 + 0x10);
      local_334 = FLOAT_803e1ad8 + *(float *)(param_3 + 0x14);
    }
    else {
      local_33c = FLOAT_803e1ad8 + *(float *)(param_1 + 0x18);
      local_338 = FLOAT_803e1ad8 + *(float *)(param_1 + 0x1c);
      local_334 = FLOAT_803e1ad8 + *(float *)(param_1 + 0x20);
    }
  }
  local_310 = 0;
  local_364 = param_1;
  local_2ec = local_2e8;
  (**(code **)(*DAT_803dd6fc + 8))(&local_368,0,9,&DAT_803160b8,8,&DAT_80316114,0x156,0);
  return;
}

