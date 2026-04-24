#include "ghidra_import.h"
#include "main/dll/savegame.h"

extern uint FUN_80017690();
extern uint FUN_80017760();
extern int FUN_80286834();
extern int FUN_8028683c();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286888();

extern undefined4 DAT_80317c48;
extern undefined4 DAT_80317cfc;
extern undefined DAT_80317d5c;
extern undefined DAT_80317d70;
extern undefined DAT_80317d98;
extern undefined DAT_80317dd0;
extern undefined4 DAT_80317ddc;
extern undefined4 DAT_80317dde;
extern undefined4 DAT_80317de0;
extern undefined4 DAT_80317de2;
extern undefined4 DAT_80317de4;
extern undefined4 DAT_80317de6;
extern undefined4 DAT_80317de8;
extern undefined4 DAT_80317e10;
extern undefined4 DAT_80317e4c;
extern undefined DAT_80317e64;
extern undefined DAT_80317e70;
extern undefined4 DAT_80317e7c;
extern undefined4 DAT_80317e7e;
extern undefined4 DAT_80317e80;
extern undefined4 DAT_80317e82;
extern undefined4 DAT_80317e84;
extern undefined4 DAT_80317e86;
extern undefined4 DAT_80317e88;
extern undefined4 DAT_80317eb0;
extern undefined4 DAT_80317f84;
extern undefined DAT_80318060;
extern undefined4 DAT_803180a8;
extern undefined4 DAT_803180aa;
extern undefined4 DAT_803180ac;
extern undefined4 DAT_803180ae;
extern undefined4 DAT_803180b0;
extern undefined4 DAT_803180b2;
extern undefined4 DAT_803180b4;
extern undefined4 DAT_803180d8;
extern undefined4 DAT_80318114;
extern undefined DAT_8031812c;
extern undefined DAT_80318138;
extern undefined4 DAT_80318144;
extern undefined4 DAT_80318146;
extern undefined4 DAT_80318148;
extern undefined4 DAT_8031814a;
extern undefined4 DAT_8031814c;
extern undefined4 DAT_8031814e;
extern undefined4 DAT_80318150;
extern undefined4 DAT_80318178;
extern undefined4 DAT_803181c8;
extern undefined DAT_803181f8;
extern undefined4 DAT_80318208;
extern undefined4 DAT_8031820a;
extern undefined4 DAT_8031820c;
extern undefined4 DAT_8031820e;
extern undefined4 DAT_80318210;
extern undefined4 DAT_80318212;
extern undefined4 DAT_80318214;
extern undefined4 DAT_80318238;
extern undefined4 DAT_8031830c;
extern undefined DAT_8031839c;
extern undefined DAT_803183e8;
extern undefined4 DAT_80318430;
extern undefined4 DAT_80318432;
extern undefined4 DAT_80318434;
extern undefined4 DAT_80318436;
extern undefined4 DAT_80318438;
extern undefined4 DAT_8031843a;
extern undefined4 DAT_8031843c;
extern undefined4 DAT_80318460;
extern undefined4 DAT_8031849c;
extern undefined DAT_803184b4;
extern undefined DAT_803184c0;
extern undefined4 DAT_803184cc;
extern undefined4 DAT_803184ce;
extern undefined4 DAT_803184d0;
extern undefined4 DAT_803184d2;
extern undefined4 DAT_803184d4;
extern undefined4 DAT_803184d6;
extern undefined4 DAT_803184d8;
extern undefined DAT_80318500;
extern undefined DAT_803185b4;
extern undefined4 DAT_80318668;
extern undefined DAT_803186dc;
extern undefined4 DAT_80318714;
extern undefined4 DAT_80318716;
extern undefined4 DAT_80318718;
extern undefined4 DAT_8031871a;
extern undefined4 DAT_8031871c;
extern undefined4 DAT_8031871e;
extern undefined4 DAT_80318720;
extern undefined4 DAT_80318748;
extern undefined4 DAT_80318784;
extern undefined DAT_8031879c;
extern undefined DAT_803187a8;
extern undefined4 DAT_803187b4;
extern undefined4 DAT_803187b6;
extern undefined4 DAT_803187b8;
extern undefined4 DAT_803187ba;
extern undefined4 DAT_803187bc;
extern undefined4 DAT_803187be;
extern undefined4 DAT_803187c0;
extern undefined DAT_803dc588;
extern undefined DAT_803dc590;
extern undefined DAT_803dc598;
extern undefined DAT_803dc5a0;
extern undefined DAT_803dc5a8;
extern undefined DAT_803dc5b0;
extern undefined4* DAT_803dd6fc;
extern f64 DOUBLE_803e1ee0;
extern f64 DOUBLE_803e1f60;
extern f32 FLOAT_803e1e58;
extern f32 FLOAT_803e1e5c;
extern f32 FLOAT_803e1e60;
extern f32 FLOAT_803e1e64;
extern f32 FLOAT_803e1e68;
extern f32 FLOAT_803e1e6c;
extern f32 FLOAT_803e1e70;
extern f32 FLOAT_803e1e74;
extern f32 FLOAT_803e1e78;
extern f32 FLOAT_803e1e7c;
extern f32 FLOAT_803e1e80;
extern f32 FLOAT_803e1e84;
extern f32 FLOAT_803e1e88;
extern f32 FLOAT_803e1e90;
extern f32 FLOAT_803e1e94;
extern f32 FLOAT_803e1e98;
extern f32 FLOAT_803e1e9c;
extern f32 FLOAT_803e1ea0;
extern f32 FLOAT_803e1ea4;
extern f32 FLOAT_803e1ea8;
extern f32 FLOAT_803e1eac;
extern f32 FLOAT_803e1eb0;
extern f32 FLOAT_803e1eb4;
extern f32 FLOAT_803e1eb8;
extern f32 FLOAT_803e1ec0;
extern f32 FLOAT_803e1ec4;
extern f32 FLOAT_803e1ec8;
extern f32 FLOAT_803e1ecc;
extern f32 FLOAT_803e1ed0;
extern f32 FLOAT_803e1ed4;
extern f32 FLOAT_803e1ed8;
extern f32 FLOAT_803e1ee8;
extern f32 FLOAT_803e1eec;
extern f32 FLOAT_803e1ef0;
extern f32 FLOAT_803e1ef4;
extern f32 FLOAT_803e1ef8;
extern f32 FLOAT_803e1efc;
extern f32 FLOAT_803e1f00;
extern f32 FLOAT_803e1f04;
extern f32 FLOAT_803e1f08;
extern f32 FLOAT_803e1f0c;
extern f32 FLOAT_803e1f10;
extern f32 FLOAT_803e1f18;
extern f32 FLOAT_803e1f1c;
extern f32 FLOAT_803e1f20;
extern f32 FLOAT_803e1f24;
extern f32 FLOAT_803e1f28;
extern f32 FLOAT_803e1f2c;
extern f32 FLOAT_803e1f30;
extern f32 FLOAT_803e1f34;
extern f32 FLOAT_803e1f38;
extern f32 FLOAT_803e1f40;
extern f32 FLOAT_803e1f44;
extern f32 FLOAT_803e1f48;
extern f32 FLOAT_803e1f4c;
extern f32 FLOAT_803e1f50;
extern f32 FLOAT_803e1f54;
extern f32 FLOAT_803e1f58;
extern f32 FLOAT_803e1f68;
extern f32 FLOAT_803e1f6c;
extern f32 FLOAT_803e1f70;
extern f32 FLOAT_803e1f74;
extern f32 FLOAT_803e1f78;
extern f32 FLOAT_803e1f7c;
extern f32 FLOAT_803e1f80;
extern f32 FLOAT_803e1f84;
extern f32 FLOAT_803e1f88;
extern f32 FLOAT_803e1f8c;
extern f32 FLOAT_803e1f90;
extern f32 FLOAT_803e1f98;
extern f32 FLOAT_803e1f9c;
extern f32 FLOAT_803e1fa0;
extern f32 FLOAT_803e1fa4;
extern f32 FLOAT_803e1fa8;
extern f32 FLOAT_803e1fac;
extern f32 FLOAT_803e1fb0;
extern f32 FLOAT_803e1fb4;
extern f32 FLOAT_803e1fb8;
extern f32 FLOAT_803e1fbc;
extern f32 FLOAT_803e1fc0;
extern f32 FLOAT_803e1fc4;
extern f32 FLOAT_803e1fc8;
extern f32 FLOAT_803e1fcc;
extern f32 FLOAT_803e1fd0;
extern f32 FLOAT_803e1fd4;
extern f32 FLOAT_803e1fd8;
extern f32 FLOAT_803e1fdc;
extern f32 FLOAT_803e1fe0;
extern f32 FLOAT_803e1fe4;
extern f32 FLOAT_803e1fe8;

/*
 * --INFO--
 *
 * Function: FUN_800fa5d8
 * EN v1.0 Address: 0x800FA5D8
 * EN v1.0 Size: 108b
 * EN v1.1 Address: 0x800FA874
 * EN v1.1 Size: 1056b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800fa5d8(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
{
  int iVar1;
  undefined2 extraout_r4;
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
  char local_32b;
  undefined4 local_328;
  float local_324;
  float local_320;
  float local_31c;
  undefined *local_318;
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
  undefined *local_288;
  undefined2 local_284;
  undefined local_282;
  undefined4 local_280;
  float local_27c;
  float local_278;
  float local_274;
  undefined4 local_270;
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
  undefined4 local_208;
  float local_204;
  float local_200;
  float local_1fc;
  undefined *local_1f8;
  undefined2 local_1f4;
  undefined local_1f2;
  undefined4 local_1f0;
  float local_1ec;
  float local_1e8;
  float local_1e4;
  undefined *local_1e0;
  undefined2 local_1dc;
  undefined local_1da;
  undefined4 local_1d8;
  float local_1d4;
  float local_1d0;
  float local_1cc;
  undefined *local_1c8;
  undefined2 local_1c4;
  undefined local_1c2;
  undefined4 local_1c0;
  float local_1bc;
  float local_1b8;
  float local_1b4;
  undefined *local_1b0;
  undefined2 local_1ac;
  undefined local_1aa;
  undefined4 local_1a8;
  float local_1a4;
  float local_1a0;
  float local_19c;
  undefined4 local_198;
  undefined2 local_194;
  undefined local_192;
  undefined4 local_190;
  float local_18c;
  float local_188;
  float local_184;
  undefined *local_180;
  undefined2 local_17c;
  undefined local_17a;
  undefined4 local_178;
  float local_174;
  float local_170;
  float local_16c;
  undefined *local_168;
  undefined2 local_164;
  undefined local_162;
  undefined auStack_160 [352];
  
  local_384 = FUN_80286834();
  local_388 = &local_328;
  local_312 = 0;
  local_314 = 0x12;
  local_318 = &DAT_80317d98;
  local_328 = 4;
  local_324 = FLOAT_803e1e58;
  local_320 = FLOAT_803e1e58;
  local_31c = FLOAT_803e1e58;
  local_2fa = 0;
  local_2fc = 9;
  local_300 = &DAT_80317d5c;
  local_310 = 8;
  local_30c = FLOAT_803e1e58;
  local_308 = FLOAT_803e1e58;
  local_304 = FLOAT_803e1e5c;
  local_2e2 = 0;
  local_2e4 = 9;
  local_2e8 = &DAT_80317d70;
  local_2f8 = 2;
  local_2f4 = FLOAT_803e1e60;
  local_2f0 = FLOAT_803e1e64;
  local_2ec = FLOAT_803e1e60;
  local_2ca = 0;
  local_2cc = 0x12;
  local_2d0 = &DAT_80317d98;
  local_2e0 = 2;
  local_2dc = FLOAT_803e1e68;
  local_2d8 = FLOAT_803e1e6c;
  local_2d4 = FLOAT_803e1e68;
  local_2b2 = 0;
  local_2b4 = 9;
  local_2b8 = &DAT_80317d70;
  local_2c8 = 8;
  local_2c4 = FLOAT_803e1e5c;
  local_2c0 = FLOAT_803e1e58;
  local_2bc = FLOAT_803e1e5c;
  local_29a = 1;
  local_29c = 0x12;
  local_2a0 = &DAT_80317d98;
  local_2b0 = 4;
  local_2ac = FLOAT_803e1e5c;
  local_2a8 = FLOAT_803e1e58;
  local_2a4 = FLOAT_803e1e58;
  local_282 = 1;
  local_284 = 9;
  local_288 = &DAT_80317d70;
  local_298 = 2;
  local_294 = FLOAT_803e1e70;
  local_290 = FLOAT_803e1e74;
  local_28c = FLOAT_803e1e70;
  local_26a = 2;
  local_26c = 0;
  local_270 = 0;
  local_280 = 0x20;
  local_27c = FLOAT_803e1e58;
  local_278 = FLOAT_803e1e58;
  local_274 = FLOAT_803e1e58;
  local_252 = 3;
  local_254 = 9;
  local_258 = &DAT_80317d5c;
  local_268 = 8;
  local_264 = FLOAT_803e1e5c;
  local_260 = FLOAT_803e1e78;
  local_25c = FLOAT_803e1e58;
  local_23a = 3;
  local_23c = 0x12;
  local_240 = &DAT_80317d98;
  local_250 = 0x100;
  local_24c = FLOAT_803e1e58;
  local_248 = FLOAT_803e1e58;
  local_244 = FLOAT_803e1e7c;
  local_222 = 3;
  local_224 = 5;
  local_228 = &DAT_80317dd0;
  local_238 = 2;
  local_234 = FLOAT_803e1e80;
  local_230 = FLOAT_803e1e70;
  local_22c = FLOAT_803e1e80;
  local_20a = 3;
  local_20c = 4;
  local_210 = &DAT_803dc588;
  local_220 = 2;
  local_21c = FLOAT_803e1e84;
  local_218 = FLOAT_803e1e70;
  local_214 = FLOAT_803e1e84;
  local_1f2 = 4;
  local_1f4 = 9;
  local_1f8 = &DAT_80317d5c;
  local_208 = 8;
  local_204 = FLOAT_803e1e5c;
  local_200 = FLOAT_803e1e58;
  local_1fc = FLOAT_803e1e5c;
  local_1da = 4;
  local_1dc = 0x12;
  local_1e0 = &DAT_80317d98;
  local_1f0 = 0x100;
  local_1ec = FLOAT_803e1e58;
  local_1e8 = FLOAT_803e1e58;
  local_1e4 = FLOAT_803e1e7c;
  local_1c2 = 4;
  local_1c4 = 5;
  local_1c8 = &DAT_80317dd0;
  local_1d8 = 2;
  local_1d4 = FLOAT_803e1e84;
  local_1d0 = FLOAT_803e1e70;
  local_1cc = FLOAT_803e1e84;
  local_1aa = 4;
  local_1ac = 4;
  local_1b0 = &DAT_803dc588;
  local_1c0 = 2;
  local_1bc = FLOAT_803e1e80;
  local_1b8 = FLOAT_803e1e70;
  local_1b4 = FLOAT_803e1e80;
  local_192 = 5;
  local_194 = 2;
  local_198 = 0;
  local_1a8 = 0x1000;
  local_1a4 = FLOAT_803e1e70;
  local_1a0 = FLOAT_803e1e58;
  local_19c = FLOAT_803e1e58;
  local_17a = 6;
  local_17c = 0x12;
  local_180 = &DAT_80317d98;
  local_190 = 4;
  local_18c = FLOAT_803e1e58;
  local_188 = FLOAT_803e1e58;
  local_184 = FLOAT_803e1e58;
  local_162 = 6;
  local_164 = 0x12;
  local_168 = &DAT_80317d98;
  local_178 = 2;
  local_174 = FLOAT_803e1e88;
  local_170 = FLOAT_803e1e70;
  local_16c = FLOAT_803e1e88;
  local_330 = 0;
  local_35c = FLOAT_803e1e58;
  local_358 = FLOAT_803e1e58;
  local_354 = FLOAT_803e1e58;
  local_368 = FLOAT_803e1e58;
  local_364 = FLOAT_803e1e58;
  local_360 = FLOAT_803e1e58;
  local_350 = FLOAT_803e1e70;
  local_348 = 1;
  local_34c = 0;
  local_32f = 0x12;
  local_32e = 0;
  local_32d = 0xc;
  iVar1 = (int)(auStack_160 + -(int)local_388) / 0x18 +
          ((int)(auStack_160 + -(int)local_388) >> 0x1f);
  local_32b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_342 = DAT_80317ddc;
  local_340 = DAT_80317dde;
  local_33e = DAT_80317de0;
  local_33c = DAT_80317de2;
  local_33a = DAT_80317de4;
  local_338 = DAT_80317de6;
  local_336 = DAT_80317de8;
  local_334 = param_4 | 0x1000082;
  if ((param_4 & 1) != 0) {
    if (local_384 == 0) {
      local_35c = FLOAT_803e1e58 + *(float *)(param_3 + 0xc);
      local_358 = FLOAT_803e1e58 + *(float *)(param_3 + 0x10);
      local_354 = FLOAT_803e1e58 + *(float *)(param_3 + 0x14);
    }
    else {
      local_35c = FLOAT_803e1e58 + *(float *)(local_384 + 0x18);
      local_358 = FLOAT_803e1e58 + *(float *)(local_384 + 0x1c);
      local_354 = FLOAT_803e1e58 + *(float *)(local_384 + 0x20);
    }
  }
  local_344 = extraout_r4;
  (**(code **)(*DAT_803dd6fc + 8))(&local_388,0,0x12,&DAT_80317c48,0x10,&DAT_80317cfc,0x45,0);
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800fa644
 * EN v1.0 Address: 0x800FA644
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x800FAC94
 * EN v1.1 Size: 944b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800fa644(int param_1,int param_2,int param_3,uint param_4,undefined4 param_5,float *param_6
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
  
  local_2cc = FLOAT_803e1e90;
  if (param_6 != (float *)0x0) {
    local_2cc = *param_6;
  }
  local_2f2 = 0;
  local_2f4 = 5;
  local_2f8 = &DAT_80317e70;
  local_308 = 4;
  local_304 = FLOAT_803e1e94;
  local_300 = FLOAT_803e1e94;
  local_2fc = FLOAT_803e1e94;
  local_2da = 0;
  local_2dc = 1;
  local_2e0 = &DAT_803dc590;
  local_2f0 = 4;
  if (param_2 == 1) {
    local_2ec = FLOAT_803e1e98;
  }
  else {
    local_2ec = FLOAT_803e1e9c;
  }
  local_2e8 = FLOAT_803e1e94;
  local_2e4 = FLOAT_803e1e94;
  local_2c2 = 0;
  local_2c4 = 6;
  local_2c8 = &DAT_80317e64;
  local_2d8 = 2;
  if (param_2 == 1) {
    local_2cc = FLOAT_803e1ea0 * local_2cc;
  }
  else {
    local_2cc = FLOAT_803e1ea4 * local_2cc;
  }
  local_2aa = 1;
  local_2ac = 6;
  local_2b0 = &DAT_80317e64;
  local_2c0 = 0x4000;
  local_2bc = FLOAT_803e1ea8;
  local_2b8 = FLOAT_803e1e90;
  local_2b4 = FLOAT_803e1e94;
  local_292 = 1;
  local_294 = 6;
  local_298 = &DAT_80317e64;
  local_2a8 = 2;
  local_2a4 = FLOAT_803e1eac;
  local_2a0 = FLOAT_803e1eac;
  local_29c = FLOAT_803e1eb0;
  local_27a = 2;
  local_27c = 6;
  local_280 = &DAT_80317e64;
  local_290 = 0x4000;
  local_28c = FLOAT_803e1ea8;
  local_288 = FLOAT_803e1e90;
  local_284 = FLOAT_803e1e94;
  local_262 = 2;
  local_264 = 6;
  local_268 = &DAT_80317e64;
  local_278 = 2;
  local_274 = FLOAT_803e1eb4;
  local_270 = FLOAT_803e1eb4;
  local_26c = FLOAT_803e1e90;
  local_24a = 3;
  local_24c = 6;
  local_250 = &DAT_80317e64;
  local_260 = 0x4000;
  local_25c = FLOAT_803e1ea8;
  local_258 = FLOAT_803e1e90;
  local_254 = FLOAT_803e1e94;
  local_232 = 3;
  local_234 = 1;
  local_238 = &DAT_803dc590;
  local_248 = 4;
  local_244 = FLOAT_803e1e94;
  local_240 = FLOAT_803e1e94;
  local_23c = FLOAT_803e1e94;
  local_310 = 0;
  local_324 = (undefined2)param_2;
  local_33c = FLOAT_803e1e94;
  local_338 = FLOAT_803e1e94;
  local_334 = FLOAT_803e1e94;
  local_348 = FLOAT_803e1e94;
  local_344 = FLOAT_803e1e94;
  local_340 = FLOAT_803e1e94;
  local_330 = FLOAT_803e1eb8;
  local_328 = 1;
  local_32c = 0;
  local_30f = 6;
  local_30e = 0;
  local_30d = 0;
  local_30b = 9;
  local_322 = DAT_80317e7c;
  local_320 = DAT_80317e7e;
  local_31e = DAT_80317e80;
  local_31c = DAT_80317e82;
  local_31a = DAT_80317e84;
  local_318 = DAT_80317e86;
  local_316 = DAT_80317e88;
  local_368 = &local_308;
  local_314 = param_4 | 0x4000400;
  if ((param_4 & 1) != 0) {
    if ((param_1 == 0) || (param_3 == 0)) {
      if (param_1 == 0) {
        if (param_3 != 0) {
          local_33c = FLOAT_803e1e94 + *(float *)(param_3 + 0xc);
          local_338 = FLOAT_803e1e94 + *(float *)(param_3 + 0x10);
          local_334 = FLOAT_803e1e94 + *(float *)(param_3 + 0x14);
        }
      }
      else {
        local_33c = FLOAT_803e1e94 + *(float *)(param_1 + 0x18);
        local_338 = FLOAT_803e1e94 + *(float *)(param_1 + 0x1c);
        local_334 = FLOAT_803e1e94 + *(float *)(param_1 + 0x20);
      }
    }
    else {
      local_33c = FLOAT_803e1e94 + *(float *)(param_1 + 0x18) + *(float *)(param_3 + 0xc);
      local_338 = FLOAT_803e1e94 + *(float *)(param_1 + 0x1c) + *(float *)(param_3 + 0x10);
      local_334 = FLOAT_803e1e94 + *(float *)(param_1 + 0x20) + *(float *)(param_3 + 0x14);
    }
  }
  local_364 = param_1;
  local_2d4 = local_2cc;
  local_2d0 = local_2cc;
  (**(code **)(*DAT_803dd6fc + 8))(&local_368,0,6,&DAT_80317e10,4,&DAT_80317e4c,0x3c,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800fa6a8
 * EN v1.0 Address: 0x800FA6A8
 * EN v1.0 Size: 120b
 * EN v1.1 Address: 0x800FB044
 * EN v1.1 Size: 720b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800fa6a8(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
{
  int iVar1;
  int iVar2;
  undefined2 extraout_r4;
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
  char local_32b;
  undefined4 local_328;
  float local_324;
  float local_320;
  float local_31c;
  undefined *local_318;
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
  undefined auStack_298 [624];
  undefined4 local_28;
  uint uStack_24;
  
  iVar2 = FUN_8028683c();
  local_312 = 0;
  local_314 = 0x15;
  local_318 = &DAT_80318060;
  local_328 = 4;
  local_324 = FLOAT_803e1ec0;
  local_320 = FLOAT_803e1ec0;
  local_31c = FLOAT_803e1ec0;
  local_2fa = 0;
  local_2fc = 0x15;
  local_300 = &DAT_80318060;
  local_310 = 2;
  uStack_24 = FUN_80017760(0,10);
  uStack_24 = uStack_24 ^ 0x80000000;
  local_28 = 0x43300000;
  local_30c = FLOAT_803e1ec8 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e1ee0) +
              FLOAT_803e1ec4;
  local_308 = FLOAT_803e1ecc;
  local_2e2 = 1;
  local_2e4 = 0x15;
  local_2e8 = &DAT_80318060;
  local_2f8 = 4;
  local_2f4 = FLOAT_803e1ed0;
  local_2f0 = FLOAT_803e1ec0;
  local_2ec = FLOAT_803e1ec0;
  local_2ca = 1;
  local_2cc = 0x15;
  local_2d0 = &DAT_80318060;
  local_2e0 = 0x4000;
  local_2dc = FLOAT_803e1ed4;
  local_2d8 = FLOAT_803e1ec0;
  local_2d4 = FLOAT_803e1ec0;
  local_2b2 = 2;
  local_2b4 = 0x15;
  local_2b8 = &DAT_80318060;
  local_2c8 = 4;
  local_2c4 = FLOAT_803e1ec0;
  local_2c0 = FLOAT_803e1ec0;
  local_2bc = FLOAT_803e1ec0;
  local_29a = 2;
  local_29c = 0x15;
  local_2a0 = &DAT_80318060;
  local_2b0 = 0x4000;
  local_2ac = FLOAT_803e1ed4;
  local_2a8 = FLOAT_803e1ec0;
  local_2a4 = FLOAT_803e1ec0;
  local_330 = 0;
  local_35c = FLOAT_803e1ec0;
  local_358 = FLOAT_803e1ec0;
  local_354 = FLOAT_803e1ec0;
  local_368 = FLOAT_803e1ec0;
  local_364 = FLOAT_803e1ec0;
  local_360 = FLOAT_803e1ec0;
  local_350 = FLOAT_803e1ed8;
  local_348 = 2;
  local_34c = 7;
  local_32f = 0xe;
  local_32e = 0;
  local_32d = 0x1e;
  iVar1 = (int)(auStack_298 + -(int)&local_328) / 0x18 +
          ((int)(auStack_298 + -(int)&local_328) >> 0x1f);
  local_32b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_342 = DAT_803180a8;
  local_340 = DAT_803180aa;
  local_33e = DAT_803180ac;
  local_33c = DAT_803180ae;
  local_33a = DAT_803180b0;
  local_338 = DAT_803180b2;
  local_336 = DAT_803180b4;
  local_334 = param_4 | 0xc0104c0;
  if ((param_4 & 1) != 0) {
    if (iVar2 == 0) {
      local_35c = FLOAT_803e1ec0 + *(float *)(param_3 + 0xc);
      local_358 = FLOAT_803e1ec0 + *(float *)(param_3 + 0x10);
      local_354 = FLOAT_803e1ec0 + *(float *)(param_3 + 0x14);
    }
    else {
      local_35c = FLOAT_803e1ec0 + *(float *)(iVar2 + 0xc);
      local_358 = FLOAT_803e1ec0 + *(float *)(iVar2 + 0x10);
      local_354 = FLOAT_803e1ec0 + *(float *)(iVar2 + 0x14);
    }
  }
  local_388 = &local_328;
  local_384 = iVar2;
  local_344 = extraout_r4;
  local_304 = local_30c;
  (**(code **)(*DAT_803dd6fc + 8))(&local_388,0,0x15,&DAT_80317eb0,0x18,&DAT_80317f84,0x89,0);
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800fa720
 * EN v1.0 Address: 0x800FA720
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x800FB314
 * EN v1.1 Size: 944b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800fa720(int param_1,int param_2,int param_3,uint param_4,undefined4 param_5,float *param_6
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
  
  local_2cc = FLOAT_803e1ee8;
  if (param_6 != (float *)0x0) {
    local_2cc = *param_6;
  }
  local_2f2 = 0;
  local_2f4 = 5;
  local_2f8 = &DAT_80318138;
  local_308 = 4;
  local_304 = FLOAT_803e1eec;
  local_300 = FLOAT_803e1eec;
  local_2fc = FLOAT_803e1eec;
  local_2da = 0;
  local_2dc = 1;
  local_2e0 = &DAT_803dc598;
  local_2f0 = 4;
  if (param_2 == 1) {
    local_2ec = FLOAT_803e1ef0;
  }
  else {
    local_2ec = FLOAT_803e1ef4;
  }
  local_2e8 = FLOAT_803e1eec;
  local_2e4 = FLOAT_803e1eec;
  local_2c2 = 0;
  local_2c4 = 6;
  local_2c8 = &DAT_8031812c;
  local_2d8 = 2;
  if (param_2 == 1) {
    local_2cc = FLOAT_803e1ef8 * local_2cc;
  }
  else {
    local_2cc = FLOAT_803e1efc * local_2cc;
  }
  local_2aa = 1;
  local_2ac = 6;
  local_2b0 = &DAT_8031812c;
  local_2c0 = 0x4000;
  local_2bc = FLOAT_803e1f00;
  local_2b8 = FLOAT_803e1ee8;
  local_2b4 = FLOAT_803e1eec;
  local_292 = 1;
  local_294 = 6;
  local_298 = &DAT_8031812c;
  local_2a8 = 2;
  local_2a4 = FLOAT_803e1f04;
  local_2a0 = FLOAT_803e1f04;
  local_29c = FLOAT_803e1f08;
  local_27a = 2;
  local_27c = 6;
  local_280 = &DAT_8031812c;
  local_290 = 0x4000;
  local_28c = FLOAT_803e1f00;
  local_288 = FLOAT_803e1ee8;
  local_284 = FLOAT_803e1eec;
  local_262 = 2;
  local_264 = 6;
  local_268 = &DAT_8031812c;
  local_278 = 2;
  local_274 = FLOAT_803e1f0c;
  local_270 = FLOAT_803e1f0c;
  local_26c = FLOAT_803e1ee8;
  local_24a = 3;
  local_24c = 6;
  local_250 = &DAT_8031812c;
  local_260 = 0x4000;
  local_25c = FLOAT_803e1f00;
  local_258 = FLOAT_803e1ee8;
  local_254 = FLOAT_803e1eec;
  local_232 = 3;
  local_234 = 1;
  local_238 = &DAT_803dc598;
  local_248 = 4;
  local_244 = FLOAT_803e1eec;
  local_240 = FLOAT_803e1eec;
  local_23c = FLOAT_803e1eec;
  local_310 = 0;
  local_324 = (undefined2)param_2;
  local_33c = FLOAT_803e1eec;
  local_338 = FLOAT_803e1eec;
  local_334 = FLOAT_803e1eec;
  local_348 = FLOAT_803e1eec;
  local_344 = FLOAT_803e1eec;
  local_340 = FLOAT_803e1eec;
  local_330 = FLOAT_803e1f10;
  local_328 = 1;
  local_32c = 0;
  local_30f = 6;
  local_30e = 0;
  local_30d = 0;
  local_30b = 9;
  local_322 = DAT_80318144;
  local_320 = DAT_80318146;
  local_31e = DAT_80318148;
  local_31c = DAT_8031814a;
  local_31a = DAT_8031814c;
  local_318 = DAT_8031814e;
  local_316 = DAT_80318150;
  local_368 = &local_308;
  local_314 = param_4 | 0x4000410;
  if ((param_4 & 1) != 0) {
    if ((param_1 == 0) || (param_3 == 0)) {
      if (param_1 == 0) {
        if (param_3 != 0) {
          local_33c = FLOAT_803e1eec + *(float *)(param_3 + 0xc);
          local_338 = FLOAT_803e1eec + *(float *)(param_3 + 0x10);
          local_334 = FLOAT_803e1eec + *(float *)(param_3 + 0x14);
        }
      }
      else {
        local_33c = FLOAT_803e1eec + *(float *)(param_1 + 0x18);
        local_338 = FLOAT_803e1eec + *(float *)(param_1 + 0x1c);
        local_334 = FLOAT_803e1eec + *(float *)(param_1 + 0x20);
      }
    }
    else {
      local_33c = FLOAT_803e1eec + *(float *)(param_1 + 0x18) + *(float *)(param_3 + 0xc);
      local_338 = FLOAT_803e1eec + *(float *)(param_1 + 0x1c) + *(float *)(param_3 + 0x10);
      local_334 = FLOAT_803e1eec + *(float *)(param_1 + 0x20) + *(float *)(param_3 + 0x14);
    }
  }
  local_364 = param_1;
  local_2d4 = local_2cc;
  local_2d0 = local_2cc;
  (**(code **)(*DAT_803dd6fc + 8))(&local_368,0,6,&DAT_803180d8,4,&DAT_80318114,0x3c,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800fa784
 * EN v1.0 Address: 0x800FA784
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x800FB6C4
 * EN v1.1 Size: 760b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800fa784(int param_1,undefined2 param_2,int param_3)
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
  undefined4 local_314;
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
  undefined4 local_280;
  undefined2 local_27c;
  undefined local_27a;
  undefined4 local_278;
  float local_274;
  float local_270;
  float local_26c;
  undefined *local_268;
  undefined2 local_264;
  undefined local_262;
  undefined auStack_260 [604];
  
  local_368 = &local_308;
  local_2f2 = 0;
  local_2f4 = 8;
  local_2f8 = &DAT_803181f8;
  local_308 = 2;
  local_304 = FLOAT_803e1f18;
  local_300 = FLOAT_803e1f1c;
  local_2fc = FLOAT_803e1f18;
  local_2da = 0;
  local_2dc = 4;
  local_2e0 = &DAT_803dc5a0;
  local_2f0 = 8;
  local_2ec = FLOAT_803e1f20;
  local_2e8 = FLOAT_803e1f20;
  local_2e4 = FLOAT_803e1f24;
  local_2c2 = 0;
  local_2c4 = 4;
  local_2c8 = &DAT_803181f8;
  local_2d8 = 8;
  local_2d4 = FLOAT_803e1f20;
  local_2d0 = FLOAT_803e1f28;
  local_2cc = FLOAT_803e1f24;
  local_2aa = 0;
  local_2ac = 0;
  local_2b0 = 0;
  local_2c0 = 0x400000;
  local_2bc = FLOAT_803e1f24;
  local_2b8 = FLOAT_803e1f2c;
  local_2b4 = FLOAT_803e1f24;
  local_292 = 1;
  local_294 = 8;
  local_298 = &DAT_803181f8;
  local_2a8 = 2;
  local_2a4 = FLOAT_803e1f30;
  local_2a0 = FLOAT_803e1f30;
  local_29c = FLOAT_803e1f30;
  local_27a = 1;
  local_27c = 0;
  local_280 = 0;
  local_290 = 0x400000;
  local_28c = FLOAT_803e1f24;
  local_288 = FLOAT_803e1f34;
  local_284 = FLOAT_803e1f24;
  local_262 = 2;
  local_264 = 8;
  local_268 = &DAT_803181f8;
  local_278 = 4;
  local_274 = FLOAT_803e1f24;
  local_270 = FLOAT_803e1f24;
  local_26c = FLOAT_803e1f24;
  local_310 = 0;
  local_33c = FLOAT_803e1f24;
  local_338 = FLOAT_803e1f24;
  local_334 = FLOAT_803e1f24;
  local_348 = FLOAT_803e1f24;
  local_344 = FLOAT_803e1f24;
  local_340 = FLOAT_803e1f24;
  local_330 = FLOAT_803e1f38;
  local_328 = 1;
  local_32c = 0;
  local_30f = 8;
  local_30e = 0;
  local_30d = 0x3c;
  iVar1 = (int)(auStack_260 + -(int)local_368) / 0x18 +
          ((int)(auStack_260 + -(int)local_368) >> 0x1f);
  local_30b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_322 = DAT_80318208;
  local_320 = DAT_8031820a;
  local_31e = DAT_8031820c;
  local_31c = DAT_8031820e;
  local_31a = DAT_80318210;
  local_318 = DAT_80318212;
  local_316 = DAT_80318214;
  local_314 = 0x4002400;
  local_364 = param_1;
  local_324 = param_2;
  (**(code **)(*DAT_803dd6fc + 8))(&local_368,0,8,&DAT_80318178,8,&DAT_803181c8,0x46,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800fa7e8
 * EN v1.0 Address: 0x800FA7E8
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x800FB9BC
 * EN v1.1 Size: 800b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800fa7e8(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
{
  int iVar1;
  uint uVar2;
  undefined2 extraout_r4;
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
  undefined *local_318;
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
  undefined *local_288;
  undefined2 local_284;
  undefined local_282;
  undefined4 local_28;
  uint uStack_24;
  
  iVar1 = FUN_8028683c();
  uVar2 = FUN_80017690(0x63c);
  if (uVar2 == 0) {
    local_312 = 0;
    local_314 = 0x15;
    local_318 = &DAT_803183e8;
    local_328 = 4;
    local_324 = FLOAT_803e1f40;
    local_320 = FLOAT_803e1f40;
    local_31c = FLOAT_803e1f40;
    local_2fa = 0;
    local_2fc = 0x15;
    local_300 = &DAT_803183e8;
    local_310 = 2;
    uVar2 = FUN_80017690(0x4e9);
    if (uVar2 == 0) {
      uStack_24 = FUN_80017760(5,10);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_30c = FLOAT_803e1f48 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e1f60)
      ;
    }
    else {
      local_30c = FLOAT_803e1f44;
    }
    local_308 = FLOAT_803e1f4c;
    local_304 = local_30c;
    local_2e2 = 1;
    local_2e4 = 7;
    local_2e8 = &DAT_8031839c;
    local_2f8 = 2;
    local_2f4 = FLOAT_803e1f50;
    local_2f0 = FLOAT_803e1f54;
    local_2ec = FLOAT_803e1f50;
    local_2ca = 1;
    local_2cc = 0x15;
    local_2d0 = &DAT_803183e8;
    local_2e0 = 4;
    local_2dc = FLOAT_803e1f58;
    local_2d8 = FLOAT_803e1f40;
    local_2d4 = FLOAT_803e1f40;
    local_2b2 = 1;
    local_2b4 = 0x15;
    local_2b8 = &DAT_803183e8;
    local_2c8 = 0x4000;
    local_2c4 = FLOAT_803e1f40;
    local_2c0 = FLOAT_803e1f50;
    local_2bc = FLOAT_803e1f40;
    local_29a = 2;
    local_29c = 0x15;
    local_2a0 = &DAT_803183e8;
    local_2b0 = 4;
    local_2ac = FLOAT_803e1f40;
    local_2a8 = FLOAT_803e1f40;
    local_2a4 = FLOAT_803e1f40;
    local_282 = 2;
    local_284 = 0x15;
    local_288 = &DAT_803183e8;
    local_298 = 0x4000;
    local_294 = FLOAT_803e1f40;
    local_290 = FLOAT_803e1f50;
    local_28c = FLOAT_803e1f40;
    local_330 = 0;
    local_35c = FLOAT_803e1f40;
    local_358 = FLOAT_803e1f40;
    local_354 = FLOAT_803e1f40;
    local_368 = FLOAT_803e1f40;
    local_364 = FLOAT_803e1f40;
    local_360 = FLOAT_803e1f40;
    local_350 = FLOAT_803e1f50;
    local_348 = 2;
    local_34c = 7;
    local_32f = 0xe;
    local_32e = 0;
    local_32d = 0;
    local_32b = 7;
    local_342 = DAT_80318430;
    local_340 = DAT_80318432;
    local_33e = DAT_80318434;
    local_33c = DAT_80318436;
    local_33a = DAT_80318438;
    local_338 = DAT_8031843a;
    local_336 = DAT_8031843c;
    local_388 = &local_328;
    local_334 = param_4 | 0xc0104c0;
    if ((param_4 & 1) != 0) {
      if (iVar1 == 0) {
        local_35c = FLOAT_803e1f40 + *(float *)(param_3 + 0xc);
        local_358 = FLOAT_803e1f40 + *(float *)(param_3 + 0x10);
        local_354 = FLOAT_803e1f40 + *(float *)(param_3 + 0x14);
      }
      else {
        local_35c = FLOAT_803e1f40 + *(float *)(iVar1 + 0xc);
        local_358 = FLOAT_803e1f40 + *(float *)(iVar1 + 0x10);
        local_354 = FLOAT_803e1f40 + *(float *)(iVar1 + 0x14);
      }
    }
    local_384 = iVar1;
    local_344 = extraout_r4;
    (**(code **)(*DAT_803dd6fc + 8))(&local_388,0,0x15,&DAT_80318238,0x18,&DAT_8031830c,0x89,0);
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800fa880
 * EN v1.0 Address: 0x800FA880
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x800FBCDC
 * EN v1.1 Size: 944b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800fa880(int param_1,int param_2,int param_3,uint param_4,undefined4 param_5,float *param_6
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
  
  local_2cc = FLOAT_803e1f68;
  if (param_6 != (float *)0x0) {
    local_2cc = *param_6;
  }
  local_2f2 = 0;
  local_2f4 = 5;
  local_2f8 = &DAT_803184c0;
  local_308 = 4;
  local_304 = FLOAT_803e1f6c;
  local_300 = FLOAT_803e1f6c;
  local_2fc = FLOAT_803e1f6c;
  local_2da = 0;
  local_2dc = 1;
  local_2e0 = &DAT_803dc5a8;
  local_2f0 = 4;
  if (param_2 == 1) {
    local_2ec = FLOAT_803e1f70;
  }
  else {
    local_2ec = FLOAT_803e1f74;
  }
  local_2e8 = FLOAT_803e1f6c;
  local_2e4 = FLOAT_803e1f6c;
  local_2c2 = 0;
  local_2c4 = 6;
  local_2c8 = &DAT_803184b4;
  local_2d8 = 2;
  if (param_2 == 1) {
    local_2cc = FLOAT_803e1f78 * local_2cc;
  }
  else {
    local_2cc = FLOAT_803e1f7c * local_2cc;
  }
  local_2aa = 1;
  local_2ac = 6;
  local_2b0 = &DAT_803184b4;
  local_2c0 = 0x4000;
  local_2bc = FLOAT_803e1f80;
  local_2b8 = FLOAT_803e1f68;
  local_2b4 = FLOAT_803e1f6c;
  local_292 = 1;
  local_294 = 6;
  local_298 = &DAT_803184b4;
  local_2a8 = 2;
  local_2a4 = FLOAT_803e1f84;
  local_2a0 = FLOAT_803e1f84;
  local_29c = FLOAT_803e1f88;
  local_27a = 2;
  local_27c = 6;
  local_280 = &DAT_803184b4;
  local_290 = 0x4000;
  local_28c = FLOAT_803e1f80;
  local_288 = FLOAT_803e1f68;
  local_284 = FLOAT_803e1f6c;
  local_262 = 2;
  local_264 = 6;
  local_268 = &DAT_803184b4;
  local_278 = 2;
  local_274 = FLOAT_803e1f8c;
  local_270 = FLOAT_803e1f8c;
  local_26c = FLOAT_803e1f68;
  local_24a = 3;
  local_24c = 6;
  local_250 = &DAT_803184b4;
  local_260 = 0x4000;
  local_25c = FLOAT_803e1f80;
  local_258 = FLOAT_803e1f68;
  local_254 = FLOAT_803e1f6c;
  local_232 = 3;
  local_234 = 1;
  local_238 = &DAT_803dc5a8;
  local_248 = 4;
  local_244 = FLOAT_803e1f6c;
  local_240 = FLOAT_803e1f6c;
  local_23c = FLOAT_803e1f6c;
  local_310 = 0;
  local_324 = (undefined2)param_2;
  local_33c = FLOAT_803e1f6c;
  local_338 = FLOAT_803e1f6c;
  local_334 = FLOAT_803e1f6c;
  local_348 = FLOAT_803e1f6c;
  local_344 = FLOAT_803e1f6c;
  local_340 = FLOAT_803e1f6c;
  local_330 = FLOAT_803e1f90;
  local_328 = 1;
  local_32c = 0;
  local_30f = 6;
  local_30e = 0;
  local_30d = 0;
  local_30b = 9;
  local_322 = DAT_803184cc;
  local_320 = DAT_803184ce;
  local_31e = DAT_803184d0;
  local_31c = DAT_803184d2;
  local_31a = DAT_803184d4;
  local_318 = DAT_803184d6;
  local_316 = DAT_803184d8;
  local_368 = &local_308;
  local_314 = param_4 | 0x4000410;
  if ((param_4 & 1) != 0) {
    if ((param_1 == 0) || (param_3 == 0)) {
      if (param_1 == 0) {
        if (param_3 != 0) {
          local_33c = FLOAT_803e1f6c + *(float *)(param_3 + 0xc);
          local_338 = FLOAT_803e1f6c + *(float *)(param_3 + 0x10);
          local_334 = FLOAT_803e1f6c + *(float *)(param_3 + 0x14);
        }
      }
      else {
        local_33c = FLOAT_803e1f6c + *(float *)(param_1 + 0x18);
        local_338 = FLOAT_803e1f6c + *(float *)(param_1 + 0x1c);
        local_334 = FLOAT_803e1f6c + *(float *)(param_1 + 0x20);
      }
    }
    else {
      local_33c = FLOAT_803e1f6c + *(float *)(param_1 + 0x18) + *(float *)(param_3 + 0xc);
      local_338 = FLOAT_803e1f6c + *(float *)(param_1 + 0x1c) + *(float *)(param_3 + 0x10);
      local_334 = FLOAT_803e1f6c + *(float *)(param_1 + 0x20) + *(float *)(param_3 + 0x14);
    }
  }
  local_364 = param_1;
  local_2d4 = local_2cc;
  local_2d0 = local_2cc;
  (**(code **)(*DAT_803dd6fc + 8))(&local_368,0,6,&DAT_80318460,4,&DAT_8031849c,0x3c,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800fa8e4
 * EN v1.0 Address: 0x800FA8E4
 * EN v1.0 Size: 220b
 * EN v1.1 Address: 0x800FC08C
 * EN v1.1 Size: 1048b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800fa8e4(undefined4 param_1,undefined4 param_2,int param_3,uint param_4,undefined4 param_5,
                 int param_6)
{
  int iVar1;
  uint uVar2;
  undefined4 uVar3;
  undefined *puVar4;
  undefined8 uVar5;
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
  short local_330;
  short local_32e;
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
  
  uVar5 = FUN_8028683c();
  iVar1 = (int)((ulonglong)uVar5 >> 0x20);
  puVar4 = &DAT_80318500;
  uVar2 = FUN_80017760(0,0x1e);
  DAT_80318716 = (short)uVar2 + 0x1e;
  local_302 = 0;
  local_304 = 0x12;
  local_308 = &DAT_803186dc;
  local_318 = 4;
  local_314 = FLOAT_803e1f98;
  local_310 = FLOAT_803e1f98;
  local_30c = FLOAT_803e1f98;
  local_2ea = 0;
  local_2ec = 0x12;
  local_2f0 = &DAT_803186dc;
  local_300 = 2;
  local_2fc = FLOAT_803e1f9c;
  local_2f4 = FLOAT_803e1f9c;
  local_2f8 = FLOAT_803e1fa0;
  local_2d2 = 1;
  local_2d4 = 0x12;
  local_2d8 = &DAT_803186dc;
  local_2e8 = 4;
  local_2e4 = FLOAT_803e1fa4;
  local_2e0 = FLOAT_803e1f98;
  local_2dc = FLOAT_803e1f98;
  local_2ba = 1;
  local_2bc = 0x12;
  local_2c0 = &DAT_803186dc;
  local_2d0 = 0x400000;
  local_2cc = FLOAT_803e1f98;
  if (param_6 == 0) {
    local_2c8 = FLOAT_803e1fac;
  }
  else {
    local_2c8 = FLOAT_803e1fa8;
  }
  local_2c4 = FLOAT_803e1f98;
  local_2a2 = 1;
  local_2a4 = 0x12;
  local_2a8 = &DAT_803186dc;
  local_2b8 = 0x4000;
  local_2b4 = FLOAT_803e1f98;
  if (param_6 == 0) {
    local_2b0 = FLOAT_803e1fb4;
  }
  else {
    local_2b0 = FLOAT_803e1fb0;
  }
  local_2ac = FLOAT_803e1f98;
  local_28a = 2;
  local_28c = 0x12;
  local_290 = &DAT_803186dc;
  local_2a0 = 4;
  local_29c = FLOAT_803e1f98;
  local_298 = FLOAT_803e1f98;
  local_294 = FLOAT_803e1f98;
  local_272 = 2;
  local_274 = 0x12;
  local_278 = &DAT_803186dc;
  local_288 = 0x400000;
  local_284 = FLOAT_803e1f98;
  if (param_6 == 0) {
    local_280 = FLOAT_803e1fac;
  }
  else {
    local_280 = FLOAT_803e1fa8;
  }
  local_27c = FLOAT_803e1f98;
  local_25a = 2;
  local_25c = 0x12;
  local_260 = &DAT_803186dc;
  local_270 = 0x4000;
  local_26c = FLOAT_803e1f98;
  if (param_6 == 0) {
    local_268 = FLOAT_803e1fb4;
  }
  else {
    local_268 = FLOAT_803e1fb0;
  }
  local_264 = FLOAT_803e1f98;
  local_242 = 2;
  local_244 = 0x12;
  local_248 = &DAT_803186dc;
  local_258 = 2;
  local_254 = FLOAT_803e1fb0;
  local_250 = FLOAT_803e1fb0;
  local_24c = FLOAT_803e1fb0;
  local_320 = 0;
  local_334 = (undefined2)uVar5;
  local_34c = FLOAT_803e1f98;
  if (param_6 == 0) {
    local_348 = FLOAT_803e1fbc;
  }
  else {
    local_348 = FLOAT_803e1fb8;
  }
  local_344 = FLOAT_803e1f98;
  local_358 = FLOAT_803e1f98;
  local_354 = FLOAT_803e1f98;
  local_350 = FLOAT_803e1f98;
  local_340 = FLOAT_803e1fb0;
  local_338 = 1;
  local_33c = 0;
  local_31f = 0x12;
  local_31e = 0;
  local_31d = 0x10;
  local_31b = 9;
  local_332 = DAT_80318714;
  local_32c = DAT_8031871a;
  local_32a = DAT_8031871c;
  local_328 = DAT_8031871e;
  local_326 = DAT_80318720;
  local_378 = &local_318;
  local_324 = param_4 | 0x4080400;
  if ((param_4 & 1) != 0) {
    if (iVar1 == 0) {
      local_34c = FLOAT_803e1f98 + *(float *)(param_3 + 0xc);
      local_348 = local_348 + *(float *)(param_3 + 0x10);
      local_344 = FLOAT_803e1f98 + *(float *)(param_3 + 0x14);
    }
    else {
      local_34c = FLOAT_803e1f98 + *(float *)(iVar1 + 0x18);
      local_348 = local_348 + *(float *)(iVar1 + 0x1c);
      local_344 = FLOAT_803e1f98 + *(float *)(iVar1 + 0x20);
    }
  }
  if ((int)uVar5 == 0) {
    uVar3 = 0x3e9;
  }
  else if ((int)uVar5 == 1) {
    uVar3 = 0x3f0;
  }
  else {
    uVar3 = 0x3f3;
  }
  if (param_6 != 0) {
    puVar4 = &DAT_803185b4;
  }
  DAT_80318718 = DAT_80318716;
  local_374 = iVar1;
  local_330 = DAT_80318716;
  local_32e = DAT_80318716;
  (**(code **)(*DAT_803dd6fc + 8))(&local_378,0,0x12,puVar4,0x10,&DAT_80318668,uVar3,0);
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800fa9c0
 * EN v1.0 Address: 0x800FA9C0
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x800FC4A4
 * EN v1.1 Size: 936b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800fa9c0(int param_1,int param_2,int param_3,uint param_4,undefined4 param_5,float *param_6
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
  
  local_2cc = FLOAT_803e1fc0;
  if (param_6 != (float *)0x0) {
    local_2cc = *param_6;
  }
  local_2f2 = 0;
  local_2f4 = 5;
  local_2f8 = &DAT_803187a8;
  local_308 = 4;
  local_304 = FLOAT_803e1fc4;
  local_300 = FLOAT_803e1fc4;
  local_2fc = FLOAT_803e1fc4;
  local_2da = 0;
  local_2dc = 1;
  local_2e0 = &DAT_803dc5b0;
  local_2f0 = 4;
  if (param_2 == 1) {
    local_2ec = FLOAT_803e1fc8;
  }
  else {
    local_2ec = FLOAT_803e1fcc;
  }
  local_2e8 = FLOAT_803e1fc4;
  local_2e4 = FLOAT_803e1fc4;
  local_2c2 = 0;
  local_2c4 = 6;
  local_2c8 = &DAT_8031879c;
  local_2d8 = 2;
  if (param_2 == 1) {
    local_2cc = FLOAT_803e1fd0 * local_2cc;
  }
  else {
    local_2cc = FLOAT_803e1fd4 * local_2cc;
  }
  local_2aa = 1;
  local_2ac = 6;
  local_2b0 = &DAT_8031879c;
  local_2c0 = 0x4000;
  local_2bc = FLOAT_803e1fd8;
  local_2b8 = FLOAT_803e1fc0;
  local_2b4 = FLOAT_803e1fc4;
  local_292 = 1;
  local_294 = 6;
  local_298 = &DAT_8031879c;
  local_2a8 = 2;
  local_2a4 = FLOAT_803e1fdc;
  local_2a0 = FLOAT_803e1fdc;
  local_29c = FLOAT_803e1fe0;
  local_27a = 2;
  local_27c = 6;
  local_280 = &DAT_8031879c;
  local_290 = 0x4000;
  local_28c = FLOAT_803e1fd8;
  local_288 = FLOAT_803e1fc0;
  local_284 = FLOAT_803e1fc4;
  local_262 = 2;
  local_264 = 6;
  local_268 = &DAT_8031879c;
  local_278 = 2;
  local_274 = FLOAT_803e1fe4;
  local_270 = FLOAT_803e1fe4;
  local_26c = FLOAT_803e1fc0;
  local_24a = 3;
  local_24c = 6;
  local_250 = &DAT_8031879c;
  local_260 = 0x4000;
  local_25c = FLOAT_803e1fd8;
  local_258 = FLOAT_803e1fc0;
  local_254 = FLOAT_803e1fc4;
  local_232 = 3;
  local_234 = 1;
  local_238 = &DAT_803dc5b0;
  local_248 = 4;
  local_244 = FLOAT_803e1fc4;
  local_240 = FLOAT_803e1fc4;
  local_23c = FLOAT_803e1fc4;
  local_310 = 0;
  local_324 = (undefined2)param_2;
  local_33c = FLOAT_803e1fc4;
  local_338 = FLOAT_803e1fc4;
  local_334 = FLOAT_803e1fc4;
  local_348 = FLOAT_803e1fc4;
  local_344 = FLOAT_803e1fc4;
  local_340 = FLOAT_803e1fc4;
  local_330 = FLOAT_803e1fe8;
  local_328 = 1;
  local_32c = 0;
  local_30f = 6;
  local_30e = 0;
  local_30d = 0;
  local_30b = 9;
  local_322 = DAT_803187b4;
  local_320 = DAT_803187b6;
  local_31e = DAT_803187b8;
  local_31c = DAT_803187ba;
  local_31a = DAT_803187bc;
  local_318 = DAT_803187be;
  local_316 = DAT_803187c0;
  local_368 = &local_308;
  local_314 = param_4 | 0x4000410;
  if ((param_4 & 1) != 0) {
    if ((param_1 == 0) || (param_3 == 0)) {
      if (param_1 == 0) {
        if (param_3 != 0) {
          local_33c = FLOAT_803e1fc4 + *(float *)(param_3 + 0xc);
          local_338 = FLOAT_803e1fc4 + *(float *)(param_3 + 0x10);
          local_334 = FLOAT_803e1fc4 + *(float *)(param_3 + 0x14);
        }
      }
      else {
        local_33c = FLOAT_803e1fc4 + *(float *)(param_1 + 0x18);
        local_338 = FLOAT_803e1fc4 + *(float *)(param_1 + 0x1c);
        local_334 = FLOAT_803e1fc4 + *(float *)(param_1 + 0x20);
      }
    }
    else {
      local_33c = FLOAT_803e1fc4 + *(float *)(param_1 + 0x18) + *(float *)(param_3 + 0xc);
      local_338 = FLOAT_803e1fc4 + *(float *)(param_1 + 0x1c) + *(float *)(param_3 + 0x10);
      local_334 = FLOAT_803e1fc4 + *(float *)(param_1 + 0x20) + *(float *)(param_3 + 0x14);
    }
  }
  local_364 = param_1;
  local_2d4 = local_2cc;
  local_2d0 = local_2cc;
  (**(code **)(*DAT_803dd6fc + 8))(&local_368,0,6,&DAT_80318748,4,&DAT_80318784,0x3c,0);
  return;
}
