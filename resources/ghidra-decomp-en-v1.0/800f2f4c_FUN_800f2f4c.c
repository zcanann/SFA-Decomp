// Function: FUN_800f2f4c
// Entry: 800f2f4c
// Size: 1196 bytes

void FUN_800f2f4c(int param_1,undefined2 param_2,short *param_3,uint param_4)

{
  undefined4 *local_388;
  int local_384;
  float local_368;
  float local_364;
  float local_360;
  float local_35c;
  float local_358;
  float local_354;
  float local_350;
  undefined4 local_34c;
  undefined4 local_348;
  undefined2 local_344;
  undefined2 local_342;
  undefined2 local_340;
  undefined2 local_33e;
  undefined2 local_33c;
  undefined2 local_33a;
  undefined2 local_338;
  undefined2 local_336;
  uint local_334;
  undefined local_330;
  undefined local_32f;
  undefined local_32e;
  undefined local_32d;
  undefined local_32b;
  undefined4 local_328;
  float local_324;
  float local_320;
  float local_31c;
  undefined4 local_318;
  undefined2 local_314;
  undefined local_312;
  undefined4 local_310;
  float local_30c;
  float local_308;
  float local_304;
  undefined *local_300;
  undefined2 local_2fc;
  undefined local_2fa;
  undefined4 local_2f8;
  float local_2f4;
  float local_2f0;
  float local_2ec;
  undefined *local_2e8;
  undefined2 local_2e4;
  undefined local_2e2;
  undefined4 local_2e0;
  float local_2dc;
  float local_2d8;
  float local_2d4;
  undefined *local_2d0;
  undefined2 local_2cc;
  undefined local_2ca;
  undefined4 local_2c8;
  float local_2c4;
  float local_2c0;
  float local_2bc;
  undefined *local_2b8;
  undefined2 local_2b4;
  undefined local_2b2;
  undefined4 local_2b0;
  float local_2ac;
  float local_2a8;
  float local_2a4;
  undefined *local_2a0;
  undefined2 local_29c;
  undefined local_29a;
  undefined4 local_298;
  float local_294;
  float local_290;
  float local_28c;
  undefined4 local_288;
  undefined2 local_284;
  undefined local_282;
  undefined4 local_280;
  float local_27c;
  float local_278;
  float local_274;
  undefined *local_270;
  undefined2 local_26c;
  undefined local_26a;
  undefined4 local_268;
  float local_264;
  float local_260;
  float local_25c;
  undefined *local_258;
  undefined2 local_254;
  undefined local_252;
  undefined4 local_250;
  float local_24c;
  float local_248;
  float local_244;
  undefined *local_240;
  undefined2 local_23c;
  undefined local_23a;
  undefined4 local_238;
  float local_234;
  float local_230;
  float local_22c;
  undefined *local_228;
  undefined2 local_224;
  undefined local_222;
  undefined4 local_220;
  float local_21c;
  float local_218;
  float local_214;
  undefined *local_210;
  undefined2 local_20c;
  undefined local_20a;
  undefined4 local_28;
  uint uStack36;
  undefined4 local_20;
  uint uStack28;
  undefined4 local_18;
  uint uStack20;
  
  local_312 = 0;
  local_314 = 200;
  local_318 = 0;
  local_328 = 0x800000;
  local_324 = FLOAT_803e0c70;
  local_320 = FLOAT_803e0c74;
  local_31c = FLOAT_803e0c74;
  local_2fa = 0;
  local_2fc = 0xe;
  local_300 = &DAT_80314a84;
  local_310 = 0x80;
  local_30c = FLOAT_803e0c74;
  local_308 = FLOAT_803e0c74;
  if (param_3 == (short *)0x0) {
    local_304 = FLOAT_803e0c74;
  }
  else {
    uStack36 = (int)*param_3 ^ 0x80000000;
    local_28 = 0x43300000;
    local_304 = (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e0ca8);
  }
  local_2e2 = 0;
  local_2e4 = 7;
  local_2e8 = &DAT_80314ab0;
  local_2f8 = 4;
  local_2f4 = FLOAT_803e0c74;
  local_2f0 = FLOAT_803e0c74;
  local_2ec = FLOAT_803e0c74;
  local_2ca = 0;
  local_2cc = 7;
  local_2d0 = &DAT_80314aa0;
  local_2e0 = 2;
  local_2dc = FLOAT_803e0c78;
  local_2d8 = FLOAT_803e0c7c;
  local_2d4 = FLOAT_803e0c78;
  local_2b2 = 0;
  local_2b4 = 7;
  local_2b8 = &DAT_80314ab0;
  local_2c8 = 2;
  local_2c0 = FLOAT_803e0c80;
  local_2c4 = FLOAT_803e0c70;
  local_29a = 1;
  local_29c = 7;
  local_2a0 = &DAT_80314ab0;
  local_2b0 = 2;
  if (param_3 == (short *)0x0) {
    local_2ac = FLOAT_803e0c88;
    local_2a8 = FLOAT_803e0c8c;
    local_2a4 = FLOAT_803e0c88;
  }
  else {
    uStack36 = (int)param_3[2] ^ 0x80000000;
    local_28 = 0x43300000;
    local_2ac = FLOAT_803e0c84 *
                FLOAT_803e0c88 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e0ca8);
    local_20 = 0x43300000;
    local_2a8 = FLOAT_803e0c84 *
                FLOAT_803e0c8c * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e0ca8);
    local_18 = 0x43300000;
    local_2a4 = FLOAT_803e0c84 *
                FLOAT_803e0c88 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e0ca8);
    uStack28 = uStack36;
    uStack20 = uStack36;
  }
  local_282 = 1;
  local_284 = 0x7a;
  local_288 = 0;
  local_298 = 0x10000;
  local_294 = FLOAT_803e0c74;
  local_290 = FLOAT_803e0c74;
  local_28c = FLOAT_803e0c74;
  local_26a = 1;
  local_26c = 0xe;
  local_270 = &DAT_80314a84;
  local_280 = 0x4000;
  local_27c = FLOAT_803e0c74;
  local_278 = FLOAT_803e0c90;
  local_274 = FLOAT_803e0c74;
  local_252 = 1;
  local_254 = 7;
  local_258 = &DAT_80314aa0;
  local_268 = 4;
  local_264 = FLOAT_803e0c94;
  local_260 = FLOAT_803e0c74;
  local_25c = FLOAT_803e0c74;
  local_23a = 2;
  local_23c = 0xe;
  local_240 = &DAT_80314a84;
  local_250 = 2;
  local_24c = FLOAT_803e0c98;
  local_248 = FLOAT_803e0c9c;
  local_244 = FLOAT_803e0c98;
  local_222 = 2;
  local_224 = 0xe;
  local_228 = &DAT_80314a84;
  local_238 = 0x4000;
  local_234 = FLOAT_803e0c74;
  local_230 = FLOAT_803e0ca0;
  local_22c = FLOAT_803e0c74;
  local_20a = 2;
  local_20c = 7;
  local_210 = &DAT_80314aa0;
  local_220 = 4;
  local_21c = FLOAT_803e0c74;
  local_218 = FLOAT_803e0c74;
  local_214 = FLOAT_803e0c74;
  local_330 = 0;
  if (param_3 == (short *)0x0) {
    local_35c = FLOAT_803e0c74;
    local_358 = FLOAT_803e0c74;
    local_354 = FLOAT_803e0c74;
  }
  else {
    local_35c = *(float *)(param_3 + 6);
    local_358 = *(float *)(param_3 + 8);
    local_354 = *(float *)(param_3 + 10);
  }
  local_368 = FLOAT_803e0c74;
  local_364 = FLOAT_803e0c74;
  local_360 = FLOAT_803e0c74;
  local_350 = FLOAT_803e0c70;
  local_348 = 1;
  local_34c = 0;
  local_32f = 0xe;
  local_32e = 0;
  local_32d = 0x10;
  local_32b = 0xb;
  local_342 = DAT_80314ac0;
  local_340 = DAT_80314ac2;
  local_33e = DAT_80314ac4;
  local_33c = DAT_80314ac6;
  local_33a = DAT_80314ac8;
  local_338 = DAT_80314aca;
  local_336 = DAT_80314acc;
  local_388 = &local_328;
  local_334 = param_4 | 0x4000400;
  if ((param_4 & 1) != 0) {
    if (param_1 == 0) {
      local_35c = local_35c + *(float *)(param_3 + 6);
      local_358 = local_358 + *(float *)(param_3 + 8);
      local_354 = local_354 + *(float *)(param_3 + 10);
    }
    else {
      local_35c = local_35c + *(float *)(param_1 + 0x18);
      local_358 = local_358 + *(float *)(param_1 + 0x1c);
      local_354 = local_354 + *(float *)(param_1 + 0x20);
    }
  }
  local_384 = param_1;
  local_344 = param_2;
  local_2bc = local_2c4;
  (**(code **)(*DAT_803dca7c + 8))(&local_388,0,0xe,&DAT_803149b0,0xc,&DAT_80314a3c,0x34,0);
  return;
}

