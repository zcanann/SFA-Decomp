// Function: FUN_800fc208
// Entry: 800fc208
// Size: 936 bytes

void FUN_800fc208(int param_1,int param_2,int param_3,uint param_4,undefined4 param_5,float *param_6
                 )

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
  undefined4 local_290;
  float local_28c;
  float local_288;
  float local_284;
  undefined *local_280;
  undefined2 local_27c;
  undefined local_27a;
  undefined4 local_278;
  float local_274;
  float local_270;
  float local_26c;
  undefined *local_268;
  undefined2 local_264;
  undefined local_262;
  undefined4 local_260;
  float local_25c;
  float local_258;
  float local_254;
  undefined *local_250;
  undefined2 local_24c;
  undefined local_24a;
  undefined4 local_248;
  float local_244;
  float local_240;
  float local_23c;
  undefined *local_238;
  undefined2 local_234;
  undefined local_232;
  
  local_2cc = FLOAT_803e1340;
  if (param_6 != (float *)0x0) {
    local_2cc = *param_6;
  }
  local_2f2 = 0;
  local_2f4 = 5;
  local_2f8 = &DAT_80317b58;
  local_308 = 4;
  local_304 = FLOAT_803e1344;
  local_300 = FLOAT_803e1344;
  local_2fc = FLOAT_803e1344;
  local_2da = 0;
  local_2dc = 1;
  local_2e0 = &DAT_803db950;
  local_2f0 = 4;
  if (param_2 == 1) {
    local_2ec = FLOAT_803e1348;
  }
  else {
    local_2ec = FLOAT_803e134c;
  }
  local_2e8 = FLOAT_803e1344;
  local_2e4 = FLOAT_803e1344;
  local_2c2 = 0;
  local_2c4 = 6;
  local_2c8 = &DAT_80317b4c;
  local_2d8 = 2;
  if (param_2 == 1) {
    local_2cc = FLOAT_803e1350 * local_2cc;
  }
  else {
    local_2cc = FLOAT_803e1354 * local_2cc;
  }
  local_2aa = 1;
  local_2ac = 6;
  local_2b0 = &DAT_80317b4c;
  local_2c0 = 0x4000;
  local_2bc = FLOAT_803e1358;
  local_2b8 = FLOAT_803e1340;
  local_2b4 = FLOAT_803e1344;
  local_292 = 1;
  local_294 = 6;
  local_298 = &DAT_80317b4c;
  local_2a8 = 2;
  local_2a4 = FLOAT_803e135c;
  local_2a0 = FLOAT_803e135c;
  local_29c = FLOAT_803e1360;
  local_27a = 2;
  local_27c = 6;
  local_280 = &DAT_80317b4c;
  local_290 = 0x4000;
  local_28c = FLOAT_803e1358;
  local_288 = FLOAT_803e1340;
  local_284 = FLOAT_803e1344;
  local_262 = 2;
  local_264 = 6;
  local_268 = &DAT_80317b4c;
  local_278 = 2;
  local_274 = FLOAT_803e1364;
  local_270 = FLOAT_803e1364;
  local_26c = FLOAT_803e1340;
  local_24a = 3;
  local_24c = 6;
  local_250 = &DAT_80317b4c;
  local_260 = 0x4000;
  local_25c = FLOAT_803e1358;
  local_258 = FLOAT_803e1340;
  local_254 = FLOAT_803e1344;
  local_232 = 3;
  local_234 = 1;
  local_238 = &DAT_803db950;
  local_248 = 4;
  local_244 = FLOAT_803e1344;
  local_240 = FLOAT_803e1344;
  local_23c = FLOAT_803e1344;
  local_310 = 0;
  local_324 = (undefined2)param_2;
  local_33c = FLOAT_803e1344;
  local_338 = FLOAT_803e1344;
  local_334 = FLOAT_803e1344;
  local_348 = FLOAT_803e1344;
  local_344 = FLOAT_803e1344;
  local_340 = FLOAT_803e1344;
  local_330 = FLOAT_803e1368;
  local_328 = 1;
  local_32c = 0;
  local_30f = 6;
  local_30e = 0;
  local_30d = 0;
  local_30b = 9;
  local_322 = DAT_80317b64;
  local_320 = DAT_80317b66;
  local_31e = DAT_80317b68;
  local_31c = DAT_80317b6a;
  local_31a = DAT_80317b6c;
  local_318 = DAT_80317b6e;
  local_316 = DAT_80317b70;
  local_368 = &local_308;
  local_314 = param_4 | 0x4000410;
  if ((param_4 & 1) != 0) {
    if ((param_1 == 0) || (param_3 == 0)) {
      if (param_1 == 0) {
        if (param_3 != 0) {
          local_33c = FLOAT_803e1344 + *(float *)(param_3 + 0xc);
          local_338 = FLOAT_803e1344 + *(float *)(param_3 + 0x10);
          local_334 = FLOAT_803e1344 + *(float *)(param_3 + 0x14);
        }
      }
      else {
        local_33c = FLOAT_803e1344 + *(float *)(param_1 + 0x18);
        local_338 = FLOAT_803e1344 + *(float *)(param_1 + 0x1c);
        local_334 = FLOAT_803e1344 + *(float *)(param_1 + 0x20);
      }
    }
    else {
      local_33c = FLOAT_803e1344 + *(float *)(param_1 + 0x18) + *(float *)(param_3 + 0xc);
      local_338 = FLOAT_803e1344 + *(float *)(param_1 + 0x1c) + *(float *)(param_3 + 0x10);
      local_334 = FLOAT_803e1344 + *(float *)(param_1 + 0x20) + *(float *)(param_3 + 0x14);
    }
  }
  local_364 = param_1;
  local_2d4 = local_2cc;
  local_2d0 = local_2cc;
  (**(code **)(*DAT_803dca7c + 8))(&local_368,0,6,&DAT_80317af8,4,&DAT_80317b34,0x3c,0);
  return;
}

