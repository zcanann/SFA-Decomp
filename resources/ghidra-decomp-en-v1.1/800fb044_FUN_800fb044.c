// Function: FUN_800fb044
// Entry: 800fb044
// Size: 712 bytes

void FUN_800fb044(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)

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
  uStack_24 = FUN_80022264(0,10);
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

