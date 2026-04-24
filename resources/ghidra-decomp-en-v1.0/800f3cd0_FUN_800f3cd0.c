// Function: FUN_800f3cd0
// Entry: 800f3cd0
// Size: 1180 bytes

void FUN_800f3cd0(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)

{
  int iVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 uVar4;
  undefined8 uVar5;
  undefined4 *local_3b8;
  int local_3b4;
  float local_398;
  float local_394;
  float local_390;
  float local_38c;
  float local_388;
  float local_384;
  float local_380;
  undefined4 local_37c;
  undefined4 local_378;
  undefined2 local_374;
  undefined2 local_372;
  undefined2 local_370;
  undefined2 local_36e;
  undefined2 local_36c;
  undefined2 local_36a;
  undefined2 local_368;
  undefined2 local_366;
  uint local_364;
  undefined local_360;
  undefined local_35f;
  undefined local_35e;
  undefined local_35d;
  char local_35b;
  undefined4 local_358;
  float local_354;
  float local_350;
  float local_34c;
  undefined *local_348;
  undefined2 local_344;
  undefined local_342;
  undefined4 local_340;
  float local_33c;
  float local_338;
  float local_334;
  undefined *local_330;
  undefined2 local_32c;
  undefined local_32a;
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
  undefined4 local_300;
  undefined2 local_2fc;
  undefined local_2fa;
  undefined4 local_2f8;
  float local_2f4;
  float local_2f0;
  float local_2ec;
  undefined4 local_2e8;
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
  undefined4 local_2b8;
  undefined2 local_2b4;
  undefined local_2b2;
  undefined4 auStack688 [150];
  undefined4 local_58;
  uint uStack84;
  undefined4 local_50;
  uint uStack76;
  undefined4 local_48;
  uint uStack68;
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  undefined4 local_30;
  uint uStack44;
  
  uVar5 = FUN_802860d4();
  local_3b4 = (int)((ulonglong)uVar5 >> 0x20);
  iVar2 = (int)uVar5;
  uVar4 = 0;
  local_342 = 0;
  local_344 = 8;
  local_348 = &DAT_80314c70;
  local_358 = 4;
  local_354 = FLOAT_803e0d08;
  local_350 = FLOAT_803e0d08;
  local_34c = FLOAT_803e0d08;
  local_32a = 0;
  local_32c = 8;
  local_330 = &DAT_80314c5c;
  local_340 = 2;
  uStack84 = FUN_800221a0(10,0xf);
  uStack84 = uStack84 ^ 0x80000000;
  local_58 = 0x43300000;
  local_33c = FLOAT_803e0d0c * (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803e0d30);
  uStack76 = FUN_800221a0(10,0xf);
  uStack76 = uStack76 ^ 0x80000000;
  local_50 = 0x43300000;
  local_338 = FLOAT_803e0d0c * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e0d30);
  uStack68 = FUN_800221a0(10,0xf);
  uStack68 = uStack68 ^ 0x80000000;
  local_48 = 0x43300000;
  local_334 = FLOAT_803e0d10 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e0d30);
  local_312 = 0;
  local_314 = 9;
  local_318 = &DAT_80314c5c;
  local_328 = 0x80;
  local_324 = FLOAT_803e0d08;
  local_320 = FLOAT_803e0d08;
  local_31c = FLOAT_803e0d14;
  local_2fa = 1;
  local_2fc = 0x9c;
  local_300 = 0;
  local_310 = 0x800000;
  local_30c = FLOAT_803e0d18;
  local_308 = FLOAT_803e0d1c;
  local_304 = FLOAT_803e0d08;
  local_2e2 = 1;
  local_2e4 = 0;
  local_2e8 = 0;
  local_2f8 = 0x400000;
  uStack60 = FUN_800221a0(0xfffff830,200);
  uStack60 = uStack60 ^ 0x80000000;
  local_40 = 0x43300000;
  local_2f4 = (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e0d30);
  uStack52 = FUN_800221a0(0xffffff38,200);
  uStack52 = uStack52 ^ 0x80000000;
  local_38 = 0x43300000;
  local_2f0 = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e0d30);
  uStack44 = FUN_800221a0(0xffffff38,200);
  uStack44 = uStack44 ^ 0x80000000;
  local_30 = 0x43300000;
  local_2ec = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e0d30);
  local_2ca = 1;
  local_2cc = 9;
  local_2d0 = &DAT_80314c5c;
  local_2e0 = 4;
  local_2dc = FLOAT_803e0d08;
  local_2d8 = FLOAT_803e0d08;
  local_2d4 = FLOAT_803e0d08;
  puVar3 = &local_2c8;
  if (iVar2 == 0) {
    local_2b2 = 3;
    local_2b4 = 0;
    local_2b8 = 0;
    local_2c8 = 0x20000000;
    local_2c4 = FLOAT_803e0d20;
    local_2c0 = FLOAT_803e0d24;
    local_2bc = FLOAT_803e0d28;
    puVar3 = auStack688;
  }
  local_374 = (undefined2)uVar5;
  if (iVar2 == 0) {
    local_388 = FLOAT_803e0d08;
  }
  else {
    local_388 = FLOAT_803e0d2c;
  }
  local_38c = FLOAT_803e0d08;
  local_398 = FLOAT_803e0d08;
  local_394 = FLOAT_803e0d08;
  local_390 = FLOAT_803e0d08;
  local_380 = FLOAT_803e0d1c;
  local_378 = 1;
  local_37c = 0;
  local_35f = 9;
  local_35e = 0;
  local_35d = 0;
  iVar1 = ((int)puVar3 - (int)&local_358) / 0x18 + ((int)puVar3 - (int)&local_358 >> 0x1f);
  local_35b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_372 = DAT_80314c80;
  local_370 = DAT_80314c82;
  local_36e = DAT_80314c84;
  local_36c = DAT_80314c86;
  local_36a = DAT_80314c88;
  local_368 = DAT_80314c8a;
  local_366 = DAT_80314c8c;
  local_3b8 = &local_358;
  local_364 = param_4 | 0x4000000;
  local_384 = local_38c;
  if ((param_4 & 1) != 0) {
    if (local_3b4 == 0) {
      local_38c = FLOAT_803e0d08 + *(float *)(param_3 + 0xc);
      local_388 = local_388 + *(float *)(param_3 + 0x10);
      local_384 = FLOAT_803e0d08 + *(float *)(param_3 + 0x14);
    }
    else {
      local_38c = FLOAT_803e0d08 + *(float *)(local_3b4 + 0x18);
      local_388 = local_388 + *(float *)(local_3b4 + 0x1c);
      local_384 = FLOAT_803e0d08 + *(float *)(local_3b4 + 0x20);
    }
  }
  if (iVar2 == 0) {
    local_360 = 0;
    uVar4 = (**(code **)(*DAT_803dca7c + 8))(&local_3b8,0,9,&DAT_80314bd0,8,&DAT_80314c2c,0x156,0);
  }
  else if (iVar2 == 1) {
    local_360 = 0;
    uVar4 = (**(code **)(*DAT_803dca7c + 8))(&local_3b8,0,9,&DAT_80314bd0,8,&DAT_80314c2c,0xc0d,0);
  }
  FUN_80286120(uVar4);
  return;
}

