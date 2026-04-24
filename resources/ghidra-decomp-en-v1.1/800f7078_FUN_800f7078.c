// Function: FUN_800f7078
// Entry: 800f7078
// Size: 1616 bytes

void FUN_800f7078(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)

{
  double dVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  undefined8 uVar5;
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
  undefined4 local_2a0;
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
  undefined4 local_28;
  uint uStack_24;
  
  uVar5 = FUN_80286838();
  iVar2 = (int)((ulonglong)uVar5 >> 0x20);
  iVar4 = (int)uVar5;
  if (iVar4 == 4) {
    local_312 = 0;
    local_314 = 0;
    local_318 = (undefined *)0x0;
    local_328 = 0x400000;
    local_324 = FLOAT_803e1bf0;
    local_320 = FLOAT_803e1bf4;
    local_31c = FLOAT_803e1bf4;
    local_2fa = 0;
    local_2fc = 2;
    local_300 = &DAT_803dc55c;
    local_310 = 2;
    local_30c = FLOAT_803e1bf8;
    local_308 = FLOAT_803e1bfc;
    local_304 = FLOAT_803e1bf8;
    local_2e2 = 0;
    local_2e4 = 4;
    local_2e8 = &DAT_803dc55c;
    local_2f8 = 0x80;
    uStack_24 = FUN_80022264(0xffff8008,0x7ff8);
    uStack_24 = uStack_24 ^ 0x80000000;
    dVar1 = (double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e1c28;
    local_2f0 = FLOAT_803e1bf4;
    local_2ec = FLOAT_803e1c00;
  }
  else {
    local_312 = 0;
    local_314 = 2;
    local_318 = &DAT_803dc550;
    local_328 = 2;
    local_308 = *(float *)(iVar2 + 8);
    local_324 = FLOAT_803e1c04 * local_308;
    local_320 = FLOAT_803e1c08 * local_308;
    local_31c = FLOAT_803e1c0c;
    local_2fa = 0;
    local_2fc = 2;
    local_300 = &DAT_803dc55c;
    local_310 = 2;
    local_308 = local_308 / *(float *)(*(int *)(iVar2 + 0x50) + 4);
    local_30c = FLOAT_803e1c10 * local_308;
    local_308 = FLOAT_803e1c08 * local_308;
    local_304 = FLOAT_803e1c0c;
    uStack_24 = FUN_80022264(0,0xfffe);
    uStack_24 = uStack_24 ^ 0x80000000;
    dVar1 = (double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e1c28;
    local_2e2 = 0;
    local_2e4 = 0;
    local_2e8 = (undefined *)0x0;
    local_2f8 = 0x80;
    local_2f0 = FLOAT_803e1c14;
    local_2ec = FLOAT_803e1bf4;
  }
  local_2f4 = (float)dVar1;
  local_28 = 0x43300000;
  local_2ca = 0;
  local_2cc = 4;
  local_2d0 = &DAT_803dc554;
  local_2e0 = 4;
  local_2dc = FLOAT_803e1bf4;
  local_2d8 = FLOAT_803e1bf4;
  local_2d4 = FLOAT_803e1bf4;
  uStack_24 = FUN_80022264(0,0xfffe);
  uStack_24 = uStack_24 ^ 0x80000000;
  local_28 = 0x43300000;
  local_2ac = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e1c28);
  local_2b2 = 1;
  local_2b4 = 2;
  local_2b8 = &DAT_803dc550;
  local_2c8 = 4;
  local_2c4 = FLOAT_803e1c18;
  local_2c0 = FLOAT_803e1bf4;
  local_2bc = FLOAT_803e1bf4;
  if (iVar4 == 4) {
    local_29a = 2;
    local_2b0 = 0x100;
    local_2ac = FLOAT_803e1c1c;
    local_2a8 = FLOAT_803e1bf4;
  }
  else {
    local_29a = 1;
    local_2b0 = 0x80;
    local_2a8 = FLOAT_803e1c14;
  }
  local_29c = 0;
  local_2a0 = 0;
  local_2a4 = FLOAT_803e1bf4;
  uStack_24 = FUN_80022264(0,0xfffe);
  uStack_24 = uStack_24 ^ 0x80000000;
  local_28 = 0x43300000;
  local_27c = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e1c28);
  if (iVar4 == 4) {
    local_298 = 0x100;
    local_280 = 0x100;
    local_27c = FLOAT_803e1c1c;
    local_278 = FLOAT_803e1bf4;
  }
  else {
    local_298 = 0x80;
    local_280 = 0x80;
    local_278 = FLOAT_803e1c14;
  }
  local_26a = 3;
  local_26c = 0;
  local_270 = 0;
  local_282 = 2;
  local_284 = 0;
  local_288 = 0;
  local_252 = 3;
  local_254 = 2;
  local_258 = &DAT_803dc550;
  local_268 = 4;
  local_264 = FLOAT_803e1c1c;
  local_28c = FLOAT_803e1bf4;
  local_260 = FLOAT_803e1bf4;
  local_25c = FLOAT_803e1bf4;
  local_23a = 3;
  local_23c = 4;
  local_240 = &DAT_803dc554;
  local_250 = 2;
  local_24c = FLOAT_803e1bfc;
  local_248 = FLOAT_803e1c20;
  local_244 = FLOAT_803e1c0c;
  local_330 = 0;
  local_344 = (undefined2)uVar5;
  local_35c = FLOAT_803e1bf4;
  local_358 = FLOAT_803e1bf4;
  local_354 = FLOAT_803e1bf4;
  local_368 = FLOAT_803e1bf4;
  local_364 = FLOAT_803e1bf4;
  local_360 = FLOAT_803e1bf4;
  local_350 = FLOAT_803e1c0c;
  local_348 = 2;
  local_34c = 0;
  local_32f = 4;
  local_32e = 0;
  local_32d = 0x20;
  local_32b = 10;
  local_342 = DAT_80316c2c;
  local_340 = DAT_80316c2e;
  local_33e = DAT_80316c30;
  local_33c = DAT_80316c32;
  local_33a = DAT_80316c34;
  local_338 = DAT_80316c36;
  local_336 = DAT_80316c38;
  local_388 = &local_328;
  if (iVar4 == 4) {
    local_334 = 0x4004400;
  }
  else {
    local_334 = 0x4006410;
  }
  local_334 = local_334 | param_4;
  if ((param_4 & 1) != 0) {
    if ((iVar2 == 0) || (param_3 == 0)) {
      if (iVar2 == 0) {
        if (param_3 != 0) {
          local_35c = FLOAT_803e1bf4 + *(float *)(param_3 + 0xc);
          local_358 = FLOAT_803e1bf4 + *(float *)(param_3 + 0x10);
          local_354 = FLOAT_803e1bf4 + *(float *)(param_3 + 0x14);
        }
      }
      else {
        local_35c = FLOAT_803e1bf4 + *(float *)(iVar2 + 0x18);
        local_358 = FLOAT_803e1bf4 + *(float *)(iVar2 + 0x1c);
        local_354 = FLOAT_803e1bf4 + *(float *)(iVar2 + 0x20);
      }
    }
    else {
      local_35c = FLOAT_803e1bf4 + *(float *)(iVar2 + 0x18) + *(float *)(param_3 + 0xc);
      local_358 = FLOAT_803e1bf4 + *(float *)(iVar2 + 0x1c) + *(float *)(param_3 + 0x10);
      local_354 = FLOAT_803e1bf4 + *(float *)(iVar2 + 0x20) + *(float *)(param_3 + 0x14);
    }
  }
  local_384 = iVar2;
  local_294 = local_27c;
  local_290 = local_278;
  local_274 = local_28c;
  uVar3 = FUN_80022264(0,1);
  (**(code **)(*DAT_803dd6fc + 8))
            (&local_388,0,4,&DAT_80316bf8,2,&DAT_80316c20,
             (int)*(short *)(&DAT_80316c3c + (iVar4 * 2 + uVar3) * 2),0);
  FUN_80286884();
  return;
}

