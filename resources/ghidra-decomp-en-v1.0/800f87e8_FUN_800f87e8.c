// Function: FUN_800f87e8
// Entry: 800f87e8
// Size: 1400 bytes

void FUN_800f87e8(int param_1,undefined2 param_2,short *param_3,uint param_4)

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
  undefined4 local_278;
  undefined2 local_274;
  undefined local_272;
  undefined4 local_270;
  float local_26c;
  float local_268;
  float local_264;
  undefined *local_260;
  undefined2 local_25c;
  undefined local_25a;
  undefined4 local_258;
  float local_254;
  float local_250;
  float local_24c;
  undefined4 local_248;
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
  undefined4 local_218;
  undefined2 local_214;
  undefined local_212;
  undefined4 local_210;
  float local_20c;
  float local_208;
  float local_204;
  undefined *local_200;
  undefined2 local_1fc;
  undefined local_1fa;
  undefined4 local_1f8;
  float local_1f4;
  float local_1f0;
  float local_1ec;
  undefined *local_1e8;
  undefined2 local_1e4;
  undefined local_1e2;
  undefined4 local_1e0;
  float local_1dc;
  float local_1d8;
  float local_1d4;
  undefined *local_1d0;
  undefined2 local_1cc;
  undefined local_1ca;
  undefined4 local_18;
  uint uStack20;
  undefined4 local_10;
  uint uStack12;
  undefined4 local_8;
  uint uStack4;
  
  local_302 = 0;
  local_304 = 0x15;
  local_308 = &DAT_80316b00;
  local_318 = 4;
  local_314 = FLOAT_803e10b0;
  local_310 = FLOAT_803e10b0;
  local_30c = FLOAT_803e10b0;
  local_2ea = 0;
  local_2ec = 0xe;
  local_2f0 = &DAT_80316ae4;
  local_300 = 2;
  if (param_3 == (short *)0x0) {
    local_2fc = FLOAT_803e10b8;
    local_2f8 = FLOAT_803e10bc;
    local_2f4 = FLOAT_803e10b8;
  }
  else {
    uStack20 = (int)param_3[2] ^ 0x80000000;
    local_18 = 0x43300000;
    local_2fc = FLOAT_803e10b4 *
                FLOAT_803e10b8 * (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e10d8);
    uStack12 = (int)*param_3 ^ 0x80000000;
    local_10 = 0x43300000;
    local_2f8 = FLOAT_803e10b4 *
                FLOAT_803e10bc * (float)((double)CONCAT44(0x43300000,uStack12) - DOUBLE_803e10d8);
    local_8 = 0x43300000;
    local_2f4 = FLOAT_803e10b4 *
                FLOAT_803e10b8 * (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e10d8);
    uStack4 = uStack20;
  }
  local_2d2 = 0;
  local_2d4 = 7;
  local_2d8 = &DAT_80316ac4;
  local_2e8 = 2;
  if (param_3 == (short *)0x0) {
    local_2e4 = FLOAT_803e10b8;
    local_2e0 = FLOAT_803e10bc;
    local_2dc = FLOAT_803e10b8;
  }
  else {
    uStack20 = (int)param_3[2] ^ 0x80000000;
    local_8 = 0x43300000;
    local_2e4 = FLOAT_803e10b4 *
                FLOAT_803e10b8 * (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e10d8);
    uStack12 = (int)*param_3 ^ 0x80000000;
    local_10 = 0x43300000;
    local_2e0 = FLOAT_803e10b4 *
                FLOAT_803e10c0 * (float)((double)CONCAT44(0x43300000,uStack12) - DOUBLE_803e10d8);
    local_18 = 0x43300000;
    local_2dc = FLOAT_803e10b4 *
                FLOAT_803e10b8 * (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e10d8);
    uStack4 = uStack20;
  }
  local_2ba = 1;
  local_2bc = 7;
  local_2c0 = &DAT_80316ac4;
  local_2d0 = 4;
  local_2cc = FLOAT_803e10c4;
  local_2c8 = FLOAT_803e10b0;
  local_2c4 = FLOAT_803e10b0;
  local_2a2 = 1;
  local_2a4 = 7;
  local_2a8 = &DAT_80316ad4;
  local_2b8 = 4;
  local_2b4 = FLOAT_803e10c4;
  local_2b0 = FLOAT_803e10b0;
  local_2ac = FLOAT_803e10b0;
  local_28a = 1;
  local_28c = 0x15;
  local_290 = &DAT_80316b00;
  local_2a0 = 0x100;
  local_29c = FLOAT_803e10b0;
  local_298 = FLOAT_803e10b0;
  if (param_3 == (short *)0x0) {
    local_294 = FLOAT_803e10c8;
  }
  else {
    uStack4 = (int)param_3[1] ^ 0x80000000;
    local_8 = 0x43300000;
    local_294 = (float)((double)CONCAT44(0x43300000,uStack4) - DOUBLE_803e10d8);
  }
  local_272 = 2;
  local_274 = 0x3a;
  local_278 = 0;
  local_288 = 0x1800000;
  local_284 = FLOAT_803e10cc;
  local_280 = FLOAT_803e10b0;
  local_27c = FLOAT_803e10d0;
  local_25a = 2;
  local_25c = 0x15;
  local_260 = &DAT_80316b00;
  local_270 = 0x100;
  local_26c = FLOAT_803e10b0;
  local_268 = FLOAT_803e10b0;
  if (param_3 == (short *)0x0) {
    local_264 = FLOAT_803e10c8;
  }
  else {
    uStack4 = (int)param_3[1] ^ 0x80000000;
    local_8 = 0x43300000;
    local_264 = (float)((double)CONCAT44(0x43300000,uStack4) - DOUBLE_803e10d8);
  }
  local_242 = 3;
  local_244 = 0x3b8;
  local_248 = 0;
  local_258 = 0x1800000;
  local_254 = FLOAT_803e10cc;
  local_250 = FLOAT_803e10b0;
  local_24c = FLOAT_803e10d0;
  local_22a = 3;
  local_22c = 0x15;
  local_230 = &DAT_80316b00;
  local_240 = 0x100;
  local_23c = FLOAT_803e10b0;
  local_238 = FLOAT_803e10b0;
  if (param_3 == (short *)0x0) {
    local_234 = FLOAT_803e10c8;
  }
  else {
    uStack4 = (int)param_3[1] ^ 0x80000000;
    local_8 = 0x43300000;
    local_234 = (float)((double)CONCAT44(0x43300000,uStack4) - DOUBLE_803e10d8);
  }
  local_212 = 4;
  local_214 = 0;
  local_218 = 0;
  local_228 = 0x1000;
  local_224 = FLOAT_803e10d4;
  local_220 = FLOAT_803e10b0;
  local_21c = FLOAT_803e10b0;
  local_1fa = 5;
  local_1fc = 7;
  local_200 = &DAT_80316ac4;
  local_210 = 4;
  local_20c = FLOAT_803e10b0;
  local_208 = FLOAT_803e10b0;
  local_204 = FLOAT_803e10b0;
  local_1e2 = 5;
  local_1e4 = 7;
  local_1e8 = &DAT_80316ad4;
  local_1f8 = 4;
  local_1f4 = FLOAT_803e10b0;
  local_1f0 = FLOAT_803e10b0;
  local_1ec = FLOAT_803e10b0;
  local_1ca = 5;
  local_1cc = 0x15;
  local_1d0 = &DAT_80316b00;
  local_1e0 = 0x100;
  local_1dc = FLOAT_803e10b0;
  local_1d8 = FLOAT_803e10b0;
  local_1d4 = FLOAT_803e10c8;
  local_320 = 0;
  local_34c = FLOAT_803e10b0;
  local_348 = FLOAT_803e10b0;
  local_344 = FLOAT_803e10b0;
  local_358 = FLOAT_803e10b0;
  local_354 = FLOAT_803e10b0;
  local_350 = FLOAT_803e10b0;
  local_340 = FLOAT_803e10cc;
  local_338 = 2;
  local_33c = 7;
  local_31f = 0xe;
  local_31e = 0;
  local_31d = 0x1e;
  local_31b = 0xe;
  local_332 = DAT_80316b2c;
  local_330 = DAT_80316b2e;
  local_32e = DAT_80316b30;
  local_32c = DAT_80316b32;
  local_32a = DAT_80316b34;
  local_328 = DAT_80316b36;
  local_326 = DAT_80316b38;
  local_378 = &local_318;
  local_324 = param_4 | 0xc0400c0;
  if ((param_4 & 1) != 0) {
    if (param_1 == 0) {
      local_34c = FLOAT_803e10b0 + *(float *)(param_3 + 6);
      local_348 = FLOAT_803e10b0 + *(float *)(param_3 + 8);
      local_344 = FLOAT_803e10b0 + *(float *)(param_3 + 10);
    }
    else {
      local_34c = FLOAT_803e10b0 + *(float *)(param_1 + 0x18);
      local_348 = FLOAT_803e10b0 + *(float *)(param_1 + 0x1c);
      local_344 = FLOAT_803e10b0 + *(float *)(param_1 + 0x20);
    }
  }
  local_374 = param_1;
  local_334 = param_2;
  (**(code **)(*DAT_803dca7c + 8))(&local_378,0,0x15,&DAT_80316950,0x18,&DAT_80316a24,0x5e0,0);
  return;
}

