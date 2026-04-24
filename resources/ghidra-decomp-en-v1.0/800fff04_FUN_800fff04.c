// Function: FUN_800fff04
// Entry: 800fff04
// Size: 948 bytes

void FUN_800fff04(int param_1,undefined2 param_2,int param_3,uint param_4,undefined4 param_5,
                 int param_6)

{
  undefined4 *local_378;
  int local_374;
  float local_358;
  float local_354;
  float local_350;
  float local_34c;
  float local_348;
  float local_344;
  float local_340;
  undefined4 local_33c;
  undefined4 local_338;
  undefined2 local_334;
  undefined2 local_332;
  undefined2 local_330;
  undefined2 local_32e;
  undefined2 local_32c;
  undefined2 local_32a;
  undefined2 local_328;
  undefined2 local_326;
  uint local_324;
  undefined local_320;
  undefined local_31f;
  undefined local_31e;
  undefined local_31d;
  undefined local_31b;
  undefined4 local_318;
  float local_314;
  float local_310;
  float local_30c;
  undefined *local_308;
  undefined2 local_304;
  undefined local_302;
  undefined4 local_300;
  float local_2fc;
  float local_2f8;
  float local_2f4;
  undefined *local_2f0;
  undefined2 local_2ec;
  undefined local_2ea;
  undefined4 local_2e8;
  float local_2e4;
  float local_2e0;
  float local_2dc;
  undefined *local_2d8;
  undefined2 local_2d4;
  undefined local_2d2;
  undefined4 local_2d0;
  float local_2cc;
  float local_2c8;
  float local_2c4;
  undefined *local_2c0;
  undefined2 local_2bc;
  undefined local_2ba;
  undefined4 local_2b8;
  float local_2b4;
  float local_2b0;
  float local_2ac;
  undefined *local_2a8;
  undefined2 local_2a4;
  undefined local_2a2;
  undefined4 local_2a0;
  float local_29c;
  float local_298;
  float local_294;
  undefined *local_290;
  undefined2 local_28c;
  undefined local_28a;
  undefined4 local_288;
  float local_284;
  float local_280;
  float local_27c;
  undefined *local_278;
  undefined2 local_274;
  undefined local_272;
  undefined4 local_270;
  float local_26c;
  float local_268;
  float local_264;
  undefined4 local_260;
  undefined2 local_25c;
  undefined local_25a;
  undefined4 local_258;
  float local_254;
  float local_250;
  float local_24c;
  undefined *local_248;
  undefined2 local_244;
  undefined local_242;
  undefined4 local_240;
  float local_23c;
  float local_238;
  float local_234;
  undefined *local_230;
  undefined2 local_22c;
  undefined local_22a;
  undefined4 local_228;
  float local_224;
  float local_220;
  float local_21c;
  undefined *local_218;
  undefined2 local_214;
  undefined local_212;
  
  local_29c = FLOAT_803e15d4;
  if (param_6 != 0) {
    local_29c = FLOAT_803e15d0;
  }
  local_302 = 0;
  local_304 = 0xe;
  local_308 = &DAT_8031911c;
  local_318 = 4;
  local_314 = FLOAT_803e15d8;
  local_310 = FLOAT_803e15d8;
  local_30c = FLOAT_803e15d8;
  if (param_6 == 0) {
    local_2e0 = FLOAT_803e15e8;
    local_2dc = FLOAT_803e15ec;
  }
  else {
    local_2e0 = FLOAT_803e15e0;
    local_2dc = FLOAT_803e15e4;
  }
  local_2d2 = 0;
  local_2d4 = 7;
  local_2d8 = &DAT_8031910c;
  local_2e8 = 2;
  local_2ea = 0;
  local_2ec = 7;
  local_2f0 = &DAT_803190fc;
  local_2fc = FLOAT_803e15dc;
  local_300 = 2;
  local_2ba = 1;
  local_2bc = 0xe;
  local_2c0 = &DAT_8031911c;
  local_2d0 = 2;
  local_2cc = FLOAT_803e15f0;
  local_2c8 = FLOAT_803e15f4;
  local_2c4 = FLOAT_803e15f0;
  local_2a2 = 1;
  local_2a4 = 0xe;
  local_2a8 = &DAT_8031911c;
  local_2b8 = 4;
  local_2b4 = FLOAT_803e15f8;
  local_2b0 = FLOAT_803e15d8;
  local_2ac = FLOAT_803e15d8;
  local_28a = 1;
  local_28c = 0xe;
  local_290 = &DAT_8031911c;
  local_2a0 = 0x4000;
  local_298 = FLOAT_803e15d8;
  local_294 = FLOAT_803e15d8;
  local_272 = 2;
  local_274 = 0xe;
  local_278 = &DAT_8031911c;
  local_288 = 0x4000;
  local_280 = FLOAT_803e15d8;
  local_27c = FLOAT_803e15d8;
  local_25a = 3;
  local_25c = 1;
  local_260 = 0;
  local_270 = 0x2000;
  local_26c = FLOAT_803e15d8;
  local_268 = FLOAT_803e15d8;
  local_264 = FLOAT_803e15d8;
  local_242 = 4;
  local_244 = 0xe;
  local_248 = &DAT_8031911c;
  local_258 = 4;
  local_254 = FLOAT_803e15d8;
  local_250 = FLOAT_803e15d8;
  local_24c = FLOAT_803e15d8;
  local_22a = 4;
  local_22c = 0xe;
  local_230 = &DAT_8031911c;
  local_240 = 0x4000;
  local_238 = FLOAT_803e15d8;
  local_234 = FLOAT_803e15d8;
  local_212 = 4;
  local_214 = 0xe;
  local_218 = &DAT_8031911c;
  local_228 = 2;
  local_224 = FLOAT_803e15f0;
  local_220 = FLOAT_803e15fc;
  local_21c = FLOAT_803e15f0;
  local_320 = 0;
  local_34c = FLOAT_803e15d8;
  local_348 = FLOAT_803e15d8;
  local_344 = FLOAT_803e15d8;
  local_358 = FLOAT_803e15d8;
  local_354 = FLOAT_803e15d8;
  local_350 = FLOAT_803e15d8;
  local_340 = FLOAT_803e15f0;
  local_338 = 1;
  local_33c = 0;
  local_31f = 0xe;
  local_31e = 0;
  local_31d = 0x1e;
  local_31b = 0xb;
  local_332 = DAT_80319138;
  local_330 = DAT_8031913a;
  local_32e = DAT_8031913c;
  local_32c = DAT_8031913e;
  local_32a = DAT_80319140;
  local_328 = DAT_80319142;
  local_326 = DAT_80319144;
  local_378 = &local_318;
  local_324 = param_4 | 0xc010040;
  if ((param_4 & 1) != 0) {
    if (param_1 == 0) {
      local_34c = FLOAT_803e15d8 + *(float *)(param_3 + 0xc);
      local_348 = FLOAT_803e15d8 + *(float *)(param_3 + 0x10);
      local_344 = FLOAT_803e15d8 + *(float *)(param_3 + 0x14);
    }
    else {
      local_34c = FLOAT_803e15d8 + *(float *)(param_1 + 0x18);
      local_348 = FLOAT_803e15d8 + *(float *)(param_1 + 0x1c);
      local_344 = FLOAT_803e15d8 + *(float *)(param_1 + 0x20);
    }
  }
  local_374 = param_1;
  local_334 = param_2;
  local_2f8 = local_2e0;
  local_2f4 = local_2fc;
  local_2e4 = local_2dc;
  local_284 = local_29c;
  local_23c = local_29c;
  (**(code **)(*DAT_803dca7c + 8))(&local_378,0,0xe,&DAT_80319028,0xc,&DAT_803190b4,0x586,0);
  return;
}

