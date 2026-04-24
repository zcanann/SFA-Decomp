// Function: FUN_800f2cec
// Entry: 800f2cec
// Size: 600 bytes

void FUN_800f2cec(int param_1,undefined2 param_2,int param_3,uint param_4)

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
  undefined4 local_2f8;
  undefined2 local_2f4;
  undefined local_2f2;
  undefined4 local_2f0;
  float local_2ec;
  float local_2e8;
  float local_2e4;
  undefined4 local_2e0;
  undefined2 local_2dc;
  undefined local_2da;
  undefined4 local_2d8;
  float local_2d4;
  float local_2d0;
  float local_2cc;
  undefined4 local_2c8;
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
  undefined4 local_298;
  undefined2 local_294;
  undefined local_292;
  undefined4 local_290;
  float local_28c;
  float local_288;
  float local_284;
  undefined4 local_280;
  undefined2 local_27c;
  undefined local_27a;
  undefined auStack632 [632];
  
  local_368 = &local_308;
  local_2f2 = 0;
  local_2f4 = 0x8c;
  local_2f8 = 0;
  local_308 = 0x20000000;
  local_304 = FLOAT_803e0c58;
  local_300 = FLOAT_803e0c5c;
  local_2fc = FLOAT_803e0c60;
  local_2da = 0;
  local_2dc = 0;
  local_2e0 = 0;
  local_2f0 = 0x80000;
  local_2ec = FLOAT_803e0c64;
  local_2e8 = FLOAT_803e0c68;
  local_2e4 = FLOAT_803e0c64;
  local_2c2 = 1;
  local_2c4 = 0;
  local_2c8 = 0;
  local_2d8 = 0x80000;
  local_2d4 = FLOAT_803e0c64;
  local_2d0 = FLOAT_803e0c64;
  local_2cc = FLOAT_803e0c64;
  local_2aa = 3;
  local_2ac = 1;
  local_2b0 = 0;
  local_2c0 = 0x2000;
  local_2bc = FLOAT_803e0c64;
  local_2b8 = FLOAT_803e0c64;
  local_2b4 = FLOAT_803e0c64;
  local_292 = 4;
  local_294 = 0;
  local_298 = 0;
  local_2a8 = 0x80000;
  local_2a4 = FLOAT_803e0c64;
  local_2a0 = FLOAT_803e0c68;
  local_29c = FLOAT_803e0c64;
  local_27a = 5;
  local_27c = 0;
  local_280 = 0;
  local_290 = 0x20000000;
  local_28c = FLOAT_803e0c58;
  local_288 = FLOAT_803e0c5c;
  local_284 = FLOAT_803e0c60;
  local_310 = 0;
  local_33c = FLOAT_803e0c64;
  local_338 = FLOAT_803e0c64;
  local_334 = FLOAT_803e0c64;
  local_348 = FLOAT_803e0c64;
  local_344 = FLOAT_803e0c64;
  local_340 = FLOAT_803e0c64;
  local_330 = FLOAT_803e0c6c;
  local_328 = 0;
  local_32c = 0;
  local_30f = 0;
  local_30e = 0;
  local_30d = 0;
  iVar1 = (int)(auStack632 + -(int)local_368) / 0x18 + ((int)(auStack632 + -(int)local_368) >> 0x1f)
  ;
  local_30b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_322 = DAT_80314980;
  local_320 = DAT_80314982;
  local_31e = DAT_80314984;
  local_31c = DAT_80314986;
  local_31a = DAT_80314988;
  local_318 = DAT_8031498a;
  local_316 = DAT_8031498c;
  local_314 = param_4 | 0x10c00;
  if ((param_4 & 1) != 0) {
    if (param_1 == 0) {
      local_33c = FLOAT_803e0c64 + *(float *)(param_3 + 0xc);
      local_338 = FLOAT_803e0c64 + *(float *)(param_3 + 0x10);
      local_334 = FLOAT_803e0c64 + *(float *)(param_3 + 0x14);
    }
    else {
      local_33c = FLOAT_803e0c64 + *(float *)(param_1 + 0x18);
      local_338 = FLOAT_803e0c64 + *(float *)(param_1 + 0x1c);
      local_334 = FLOAT_803e0c64 + *(float *)(param_1 + 0x20);
    }
  }
  local_364 = param_1;
  local_324 = param_2;
  (**(code **)(*DAT_803dca7c + 8))(&local_368,0,0,0,0,0,0,0);
  return;
}

