// Function: FUN_800f3f6c
// Entry: 800f3f6c
// Size: 1180 bytes

void FUN_800f3f6c(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined4 *puVar4;
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
  undefined4 auStack_2b0 [150];
  undefined4 local_58;
  uint uStack_54;
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  
  uVar5 = FUN_80286838();
  iVar2 = (int)((ulonglong)uVar5 >> 0x20);
  iVar3 = (int)uVar5;
  local_342 = 0;
  local_344 = 8;
  local_348 = &DAT_803158c0;
  local_358 = 4;
  local_354 = FLOAT_803e1988;
  local_350 = FLOAT_803e1988;
  local_34c = FLOAT_803e1988;
  local_32a = 0;
  local_32c = 8;
  local_330 = &DAT_803158ac;
  local_340 = 2;
  uStack_54 = FUN_80022264(10,0xf);
  uStack_54 = uStack_54 ^ 0x80000000;
  local_58 = 0x43300000;
  local_33c = FLOAT_803e198c * (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e19b0);
  uStack_4c = FUN_80022264(10,0xf);
  uStack_4c = uStack_4c ^ 0x80000000;
  local_50 = 0x43300000;
  local_338 = FLOAT_803e198c * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e19b0);
  uStack_44 = FUN_80022264(10,0xf);
  uStack_44 = uStack_44 ^ 0x80000000;
  local_48 = 0x43300000;
  local_334 = FLOAT_803e1990 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e19b0);
  local_312 = 0;
  local_314 = 9;
  local_318 = &DAT_803158ac;
  local_328 = 0x80;
  local_324 = FLOAT_803e1988;
  local_320 = FLOAT_803e1988;
  local_31c = FLOAT_803e1994;
  local_2fa = 1;
  local_2fc = 0x9c;
  local_300 = 0;
  local_310 = 0x800000;
  local_30c = FLOAT_803e1998;
  local_308 = FLOAT_803e199c;
  local_304 = FLOAT_803e1988;
  local_2e2 = 1;
  local_2e4 = 0;
  local_2e8 = 0;
  local_2f8 = 0x400000;
  uStack_3c = FUN_80022264(0xfffff830,200);
  uStack_3c = uStack_3c ^ 0x80000000;
  local_40 = 0x43300000;
  local_2f4 = (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e19b0);
  uStack_34 = FUN_80022264(0xffffff38,200);
  uStack_34 = uStack_34 ^ 0x80000000;
  local_38 = 0x43300000;
  local_2f0 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e19b0);
  uStack_2c = FUN_80022264(0xffffff38,200);
  uStack_2c = uStack_2c ^ 0x80000000;
  local_30 = 0x43300000;
  local_2ec = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e19b0);
  local_2ca = 1;
  local_2cc = 9;
  local_2d0 = &DAT_803158ac;
  local_2e0 = 4;
  local_2dc = FLOAT_803e1988;
  local_2d8 = FLOAT_803e1988;
  local_2d4 = FLOAT_803e1988;
  puVar4 = &local_2c8;
  if (iVar3 == 0) {
    local_2b2 = 3;
    local_2b4 = 0;
    local_2b8 = 0;
    local_2c8 = 0x20000000;
    local_2c4 = FLOAT_803e19a0;
    local_2c0 = FLOAT_803e19a4;
    local_2bc = FLOAT_803e19a8;
    puVar4 = auStack_2b0;
  }
  local_374 = (undefined2)uVar5;
  if (iVar3 == 0) {
    local_388 = FLOAT_803e1988;
  }
  else {
    local_388 = FLOAT_803e19ac;
  }
  local_38c = FLOAT_803e1988;
  local_398 = FLOAT_803e1988;
  local_394 = FLOAT_803e1988;
  local_390 = FLOAT_803e1988;
  local_380 = FLOAT_803e199c;
  local_378 = 1;
  local_37c = 0;
  local_35f = 9;
  local_35e = 0;
  local_35d = 0;
  iVar1 = ((int)puVar4 - (int)&local_358) / 0x18 + ((int)puVar4 - (int)&local_358 >> 0x1f);
  local_35b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_372 = DAT_803158d0;
  local_370 = DAT_803158d2;
  local_36e = DAT_803158d4;
  local_36c = DAT_803158d6;
  local_36a = DAT_803158d8;
  local_368 = DAT_803158da;
  local_366 = DAT_803158dc;
  local_3b8 = &local_358;
  local_364 = param_4 | 0x4000000;
  local_384 = local_38c;
  if ((param_4 & 1) != 0) {
    if (iVar2 == 0) {
      local_38c = FLOAT_803e1988 + *(float *)(param_3 + 0xc);
      local_388 = local_388 + *(float *)(param_3 + 0x10);
      local_384 = FLOAT_803e1988 + *(float *)(param_3 + 0x14);
    }
    else {
      local_38c = FLOAT_803e1988 + *(float *)(iVar2 + 0x18);
      local_388 = local_388 + *(float *)(iVar2 + 0x1c);
      local_384 = FLOAT_803e1988 + *(float *)(iVar2 + 0x20);
    }
  }
  local_3b4 = iVar2;
  if (iVar3 == 0) {
    local_360 = 0;
    (**(code **)(*DAT_803dd6fc + 8))(&local_3b8,0,9,&DAT_80315820,8,&DAT_8031587c,0x156,0);
  }
  else if (iVar3 == 1) {
    local_360 = 0;
    (**(code **)(*DAT_803dd6fc + 8))(&local_3b8,0,9,&DAT_80315820,8,&DAT_8031587c,0xc0d,0);
  }
  FUN_80286884();
  return;
}

