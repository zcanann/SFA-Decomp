// Function: FUN_800ee4f8
// Entry: 800ee4f8
// Size: 1688 bytes

void FUN_800ee4f8(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  short *psVar6;
  undefined8 uVar7;
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
  undefined4 local_1e0;
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
  undefined *local_198;
  undefined2 local_194;
  undefined local_192;
  undefined4 local_190;
  float local_18c;
  float local_188;
  float local_184;
  undefined *local_180;
  undefined2 local_17c;
  undefined local_17a;
  undefined4 local_28;
  uint uStack_24;
  
  uVar7 = FUN_80286834();
  iVar1 = (int)((ulonglong)uVar7 >> 0x20);
  iVar3 = (int)uVar7;
  psVar6 = &DAT_80313828;
  if (iVar3 == 1) {
    DAT_8031393a = 0;
  }
  uVar4 = (uint)*(byte *)(*(int *)(iVar1 + 0x4c) + 0x1a);
  if (iVar3 == 2) {
    iVar5 = 0;
    do {
      if (*psVar6 < 1) {
        if (*psVar6 < 0) {
          uVar2 = FUN_80022264(0,800);
          *psVar6 = *psVar6 - (short)uVar2;
        }
      }
      else {
        uVar2 = FUN_80022264(0,800);
        *psVar6 = *psVar6 + (short)uVar2;
      }
      if (psVar6[1] < 1) {
        if (psVar6[1] < 0) {
          uVar2 = FUN_80022264(0,300);
          *psVar6 = *psVar6 - (short)uVar2;
        }
      }
      else {
        uVar2 = FUN_80022264(0,300);
        *psVar6 = *psVar6 + (short)uVar2;
      }
      if (psVar6[2] < 1) {
        if (psVar6[2] < 0) {
          uVar2 = FUN_80022264(0,800);
          *psVar6 = *psVar6 - (short)uVar2;
        }
      }
      else {
        uVar2 = FUN_80022264(0,800);
        *psVar6 = *psVar6 + (short)uVar2;
      }
      psVar6 = psVar6 + 5;
      iVar5 = iVar5 + 1;
    } while (iVar5 < 0xe);
  }
  if (iVar3 == 2) {
    local_31c = FLOAT_803e1548;
  }
  else {
    local_31c = FLOAT_803e1550;
  }
  local_2fa = 0;
  local_2fc = 7;
  local_300 = &DAT_80313928;
  local_30c = FLOAT_803e154c;
  local_310 = 8;
  local_312 = 0;
  local_314 = 7;
  local_318 = &DAT_80313918;
  local_328 = 8;
  local_2e2 = 0;
  local_2e4 = 0xe;
  local_2e8 = &DAT_803138fc;
  local_2f8 = 4;
  local_2f4 = FLOAT_803e1554;
  local_2f0 = FLOAT_803e1554;
  local_2ec = FLOAT_803e1554;
  if ((iVar3 == 3) && (param_3 != 0)) {
    local_2c0 = *(float *)(param_3 + 8);
    local_2d4 = FLOAT_803e1558 * local_2c0;
    local_2d8 = FLOAT_803e155c * local_2c0;
    local_2bc = FLOAT_803e1560 * local_2c0;
  }
  else {
    local_2d8 = FLOAT_803e155c;
    local_2d4 = FLOAT_803e1558;
    local_2c0 = FLOAT_803e1564;
    local_2bc = FLOAT_803e1560;
  }
  local_2b2 = 0;
  local_2b4 = 7;
  local_2b8 = &DAT_80313918;
  local_2c8 = 2;
  local_2ca = 0;
  local_2cc = 7;
  local_2d0 = &DAT_80313928;
  local_2e0 = 2;
  local_29a = 1;
  local_29c = 7;
  local_2a0 = &DAT_80313918;
  local_2b0 = 4;
  local_2ac = FLOAT_803e1568;
  local_2a8 = FLOAT_803e1554;
  local_2a4 = FLOAT_803e1554;
  local_282 = 1;
  local_284 = 7;
  local_288 = &DAT_80313928;
  local_298 = 4;
  local_294 = FLOAT_803e156c;
  local_290 = FLOAT_803e1554;
  local_28c = FLOAT_803e1554;
  local_26a = 1;
  local_26c = 0xe;
  local_270 = &DAT_803138fc;
  local_280 = 0x100;
  local_27c = FLOAT_803e1554;
  local_278 = FLOAT_803e1554;
  local_274 = FLOAT_803e1570;
  local_252 = 1;
  local_254 = 0xe;
  local_258 = &DAT_803138fc;
  local_268 = 0x4000;
  local_264 = FLOAT_803e1574;
  local_260 = FLOAT_803e1554;
  local_25c = FLOAT_803e1554;
  local_23a = 2;
  local_23c = 0xe;
  local_240 = &DAT_803138fc;
  local_250 = 0x100;
  local_24c = FLOAT_803e1554;
  local_248 = FLOAT_803e1554;
  local_244 = FLOAT_803e1570;
  local_222 = 2;
  local_224 = 0xe;
  local_228 = &DAT_803138fc;
  local_238 = 0x4000;
  local_234 = FLOAT_803e1574;
  local_230 = FLOAT_803e1554;
  local_22c = FLOAT_803e1554;
  local_20a = 3;
  local_20c = 0xe;
  local_210 = &DAT_803138fc;
  local_220 = 0x100;
  local_21c = FLOAT_803e1554;
  local_218 = FLOAT_803e1554;
  local_214 = FLOAT_803e1570;
  local_1f2 = 3;
  local_1f4 = 0xe;
  local_1f8 = &DAT_803138fc;
  local_208 = 0x4000;
  local_204 = FLOAT_803e1574;
  local_200 = FLOAT_803e1554;
  local_1fc = FLOAT_803e1554;
  local_1da = 4;
  local_1dc = 1;
  local_1e0 = 0;
  local_1f0 = 0x2000;
  local_1ec = FLOAT_803e1554;
  local_1e8 = FLOAT_803e1554;
  local_1e4 = FLOAT_803e1554;
  local_1c2 = 5;
  local_1c4 = 7;
  local_1c8 = &DAT_80313918;
  local_1d8 = 4;
  local_1d4 = FLOAT_803e1554;
  local_1d0 = FLOAT_803e1554;
  local_1cc = FLOAT_803e1554;
  local_1aa = 5;
  local_1ac = 7;
  local_1b0 = &DAT_80313928;
  local_1c0 = 4;
  local_1bc = FLOAT_803e1554;
  local_1b8 = FLOAT_803e1554;
  local_1b4 = FLOAT_803e1554;
  local_192 = 5;
  local_194 = 0xe;
  local_198 = &DAT_803138fc;
  local_1a8 = 0x100;
  local_1a4 = FLOAT_803e1554;
  local_1a0 = FLOAT_803e1554;
  local_19c = FLOAT_803e1570;
  local_17a = 5;
  local_17c = 0xe;
  local_180 = &DAT_803138fc;
  local_190 = 0x4000;
  local_18c = FLOAT_803e1574;
  local_188 = FLOAT_803e1554;
  local_184 = FLOAT_803e1554;
  local_330 = 0;
  local_344 = (undefined2)uVar7;
  local_35c = FLOAT_803e1554;
  local_358 = FLOAT_803e1578;
  local_354 = FLOAT_803e1554;
  local_368 = FLOAT_803e1554;
  local_364 = FLOAT_803e1554;
  local_360 = FLOAT_803e1554;
  if (uVar4 == 0) {
    local_350 = FLOAT_803e1564;
  }
  else {
    local_28 = 0x43300000;
    local_350 = FLOAT_803e157c * (float)((double)CONCAT44(0x43300000,uVar4) - DOUBLE_803e1580);
    uStack_24 = uVar4;
  }
  local_348 = 1;
  local_34c = 0;
  local_32f = 0xe;
  local_32e = 0;
  local_32d = 0x1e;
  local_32b = 0x12;
  local_342 = DAT_80313938;
  local_340 = DAT_8031393a;
  local_33e = DAT_8031393c;
  local_33c = DAT_8031393e;
  local_33a = DAT_80313940;
  local_338 = DAT_80313942;
  local_336 = DAT_80313944;
  local_388 = &local_328;
  local_334 = param_4 | 0x40000c0;
  if ((param_4 & 1) != 0) {
    if (iVar1 == 0) {
      local_35c = FLOAT_803e1554 + *(float *)(param_3 + 0xc);
      local_358 = FLOAT_803e1578 + *(float *)(param_3 + 0x10);
      local_354 = FLOAT_803e1554 + *(float *)(param_3 + 0x14);
    }
    else {
      local_35c = FLOAT_803e1554 + *(float *)(iVar1 + 0x18);
      local_358 = FLOAT_803e1578 + *(float *)(iVar1 + 0x1c);
      local_354 = FLOAT_803e1554 + *(float *)(iVar1 + 0x20);
    }
  }
  local_384 = iVar1;
  local_324 = local_31c;
  local_320 = local_31c;
  local_308 = local_30c;
  local_304 = local_30c;
  local_2dc = local_2d4;
  local_2c4 = local_2bc;
  (**(code **)(*DAT_803dd6fc + 8))(&local_388,0,0xe,&DAT_80313828,0xc,&DAT_803138b4,0x40,0);
  FUN_80286880();
  return;
}

