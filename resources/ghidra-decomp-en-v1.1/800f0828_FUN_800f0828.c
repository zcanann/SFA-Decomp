// Function: FUN_800f0828
// Entry: 800f0828
// Size: 584 bytes

void FUN_800f0828(int param_1,undefined2 param_2,int param_3,uint param_4)

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
  undefined4 local_2b0;
  undefined2 local_2ac;
  undefined local_2aa;
  undefined4 local_2a8;
  float local_2a4;
  float local_2a0;
  float local_29c;
  undefined *local_298;
  undefined2 local_294;
  undefined local_292;
  undefined4 local_290;
  float local_28c;
  float local_288;
  float local_284;
  undefined *local_280;
  undefined2 local_27c;
  undefined local_27a;
  
  local_2f2 = 0;
  local_2f4 = 5;
  local_2f8 = &DAT_803146e4;
  local_308 = 4;
  local_304 = FLOAT_803e16d8;
  local_300 = FLOAT_803e16dc;
  local_2fc = FLOAT_803e16dc;
  local_2da = 0;
  local_2dc = 5;
  local_2e0 = &DAT_803146e4;
  local_2f0 = 2;
  local_2ec = FLOAT_803e16e0;
  local_2e8 = FLOAT_803e16e0;
  local_2e4 = FLOAT_803e16e0;
  local_2c2 = 0;
  local_2c4 = 5;
  local_2c8 = &DAT_803146e4;
  local_2d8 = 8;
  local_2d4 = FLOAT_803e16e4;
  local_2d0 = FLOAT_803e16e4;
  local_2cc = FLOAT_803e16e4;
  local_2aa = 0;
  local_2ac = 0x7a;
  local_2b0 = 0;
  local_2c0 = 0x10000;
  local_2bc = FLOAT_803e16dc;
  local_2b8 = FLOAT_803e16dc;
  local_2b4 = FLOAT_803e16dc;
  local_292 = 1;
  local_294 = 5;
  local_298 = &DAT_803146e4;
  local_2a8 = 4;
  local_2a4 = FLOAT_803e16dc;
  local_2a0 = FLOAT_803e16dc;
  local_29c = FLOAT_803e16dc;
  local_27a = 1;
  local_27c = 5;
  local_280 = &DAT_803146e4;
  local_290 = 2;
  local_28c = FLOAT_803e16e8;
  local_288 = FLOAT_803e16ec;
  local_284 = FLOAT_803e16e8;
  local_310 = 0;
  local_33c = FLOAT_803e16dc;
  local_338 = FLOAT_803e16f0;
  local_334 = FLOAT_803e16dc;
  local_348 = FLOAT_803e16dc;
  local_344 = FLOAT_803e16dc;
  local_340 = FLOAT_803e16dc;
  local_330 = FLOAT_803e16ec;
  local_328 = 1;
  local_32c = 0;
  local_30f = 5;
  local_30e = 0;
  local_30d = 0x10;
  local_30b = 6;
  local_322 = DAT_803146f0;
  local_320 = DAT_803146f2;
  local_31e = DAT_803146f4;
  local_31c = DAT_803146f6;
  local_31a = DAT_803146f8;
  local_318 = DAT_803146fa;
  local_316 = DAT_803146fc;
  local_368 = &local_308;
  local_314 = param_4 | 0x4000010;
  if ((param_4 & 1) != 0) {
    if (param_1 == 0) {
      local_33c = FLOAT_803e16dc + *(float *)(param_3 + 0xc);
      local_338 = FLOAT_803e16f0 + *(float *)(param_3 + 0x10);
      local_334 = FLOAT_803e16dc + *(float *)(param_3 + 0x14);
    }
    else {
      local_33c = FLOAT_803e16dc + *(float *)(param_1 + 0x18);
      local_338 = FLOAT_803e16f0 + *(float *)(param_1 + 0x1c);
      local_334 = FLOAT_803e16dc + *(float *)(param_1 + 0x20);
    }
  }
  local_364 = param_1;
  local_324 = param_2;
  (**(code **)(*DAT_803dd6fc + 8))(&local_368,0,5,&DAT_80314690,4,&DAT_803146c4,0x5e,0);
  return;
}

