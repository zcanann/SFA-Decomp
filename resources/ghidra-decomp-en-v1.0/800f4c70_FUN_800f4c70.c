// Function: FUN_800f4c70
// Entry: 800f4c70
// Size: 812 bytes

void FUN_800f4c70(undefined4 param_1,undefined4 param_2,int param_3,uint param_4,undefined4 param_5,
                 float *param_6)

{
  int iVar1;
  undefined2 extraout_r4;
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
  char local_31b;
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
  undefined *local_260;
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
  undefined auStack552 [552];
  
  local_374 = FUN_802860dc();
  local_2f4 = FLOAT_803e0dd8;
  if (param_6 != (float *)0x0) {
    local_2f4 = *param_6;
  }
  local_378 = &local_318;
  local_302 = 0;
  local_304 = 0x15;
  local_308 = &DAT_803151e0;
  local_318 = 4;
  local_314 = FLOAT_803e0ddc;
  local_310 = FLOAT_803e0ddc;
  local_30c = FLOAT_803e0ddc;
  local_2ea = 0;
  local_2ec = 0x15;
  local_2f0 = &DAT_803151e0;
  local_300 = 2;
  local_2fc = FLOAT_803e0de0 * local_2f4;
  local_2f4 = FLOAT_803e0de4 * local_2f4;
  local_2d2 = 1;
  local_2d4 = 7;
  local_2d8 = &DAT_803151b4;
  local_2e8 = 2;
  local_2e4 = FLOAT_803e0de8;
  local_2e0 = FLOAT_803e0de8;
  local_2dc = FLOAT_803e0dd8;
  local_2ba = 2;
  local_2bc = 7;
  local_2c0 = &DAT_80315194;
  local_2d0 = 4;
  local_2cc = FLOAT_803e0dec;
  local_2c8 = FLOAT_803e0ddc;
  local_2c4 = FLOAT_803e0ddc;
  local_2a2 = 2;
  local_2a4 = 7;
  local_2a8 = &DAT_803151a4;
  local_2b8 = 4;
  local_2b4 = FLOAT_803e0dec;
  local_2b0 = FLOAT_803e0ddc;
  local_2ac = FLOAT_803e0ddc;
  local_28a = 2;
  local_28c = 7;
  local_290 = &DAT_803151a4;
  local_2a0 = 2;
  local_29c = FLOAT_803e0df0;
  local_298 = FLOAT_803e0df0;
  local_294 = FLOAT_803e0dd8;
  local_272 = 2;
  local_274 = 0x15;
  local_278 = &DAT_803151e0;
  local_288 = 0x4000;
  local_284 = FLOAT_803e0df4;
  local_280 = FLOAT_803e0df8;
  local_27c = FLOAT_803e0ddc;
  local_25a = 3;
  local_25c = 0x15;
  local_260 = &DAT_803151e0;
  local_270 = 0x4000;
  local_26c = FLOAT_803e0df4;
  local_268 = FLOAT_803e0df8;
  local_264 = FLOAT_803e0ddc;
  local_242 = 3;
  local_244 = 7;
  local_248 = &DAT_80315194;
  local_258 = 4;
  local_254 = FLOAT_803e0ddc;
  local_250 = FLOAT_803e0ddc;
  local_24c = FLOAT_803e0ddc;
  local_22a = 3;
  local_22c = 7;
  local_230 = &DAT_803151a4;
  local_240 = 4;
  local_23c = FLOAT_803e0ddc;
  local_238 = FLOAT_803e0ddc;
  local_234 = FLOAT_803e0ddc;
  local_320 = 0;
  local_34c = FLOAT_803e0ddc;
  local_348 = FLOAT_803e0ddc;
  local_344 = FLOAT_803e0ddc;
  local_358 = FLOAT_803e0ddc;
  local_354 = FLOAT_803e0ddc;
  local_350 = FLOAT_803e0ddc;
  local_340 = FLOAT_803e0dd8;
  local_338 = 2;
  local_33c = 7;
  local_31f = 0xe;
  local_31e = 0;
  local_31d = 10;
  iVar1 = (int)(auStack552 + -(int)local_378) / 0x18 + ((int)(auStack552 + -(int)local_378) >> 0x1f)
  ;
  local_31b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_332 = DAT_80315228;
  local_330 = DAT_8031522a;
  local_32e = DAT_8031522c;
  local_32c = DAT_8031522e;
  local_32a = DAT_80315230;
  local_328 = DAT_80315232;
  local_326 = DAT_80315234;
  local_324 = param_4 | 0xc010080;
  if ((param_4 & 1) != 0) {
    if (local_374 == 0) {
      local_34c = FLOAT_803e0ddc + *(float *)(param_3 + 0xc);
      local_348 = FLOAT_803e0ddc + *(float *)(param_3 + 0x10);
      local_344 = FLOAT_803e0ddc + *(float *)(param_3 + 0x14);
    }
    else {
      local_34c = FLOAT_803e0ddc + *(float *)(local_374 + 0x18);
      local_348 = FLOAT_803e0ddc + *(float *)(local_374 + 0x1c);
      local_344 = FLOAT_803e0ddc + *(float *)(local_374 + 0x20);
    }
  }
  local_334 = extraout_r4;
  local_2f8 = local_2fc;
  (**(code **)(*DAT_803dca7c + 8))(&local_378,0,0x15,&DAT_80315030,0x18,&DAT_80315104,0x89,0);
  DAT_803dd4b0 = DAT_803dd4b0 + 1;
  if (DAT_803dd4b0 == 5) {
    DAT_803dd4b0 = 0;
  }
  FUN_80286128();
  return;
}

