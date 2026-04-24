// Function: FUN_800f4410
// Entry: 800f4410
// Size: 1456 bytes

void FUN_800f4410(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)

{
  int iVar1;
  uint uVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  undefined8 uVar5;
  undefined4 *local_398;
  int local_394;
  float local_378;
  float local_374;
  float local_370;
  float local_36c;
  float local_368;
  float local_364;
  float local_360;
  undefined4 local_35c;
  undefined4 local_358;
  undefined2 local_354;
  undefined2 local_352;
  undefined2 local_350;
  undefined2 local_34e;
  undefined2 local_34c;
  undefined2 local_34a;
  undefined2 local_348;
  undefined2 local_346;
  uint local_344;
  undefined local_340;
  undefined local_33f;
  undefined local_33e;
  undefined local_33d;
  char local_33b;
  undefined4 local_338;
  float local_334;
  float local_330;
  float local_32c;
  undefined *local_328;
  undefined2 local_324;
  undefined local_322;
  undefined4 local_320;
  float local_31c;
  float local_318;
  float local_314;
  undefined *local_310;
  undefined2 local_30c;
  undefined local_30a;
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
  undefined4 local_2c8;
  undefined2 local_2c4;
  undefined local_2c2 [2];
  undefined4 local_2c0;
  float local_2bc;
  float local_2b8;
  float local_2b4;
  undefined4 local_2b0;
  undefined2 local_2ac;
  undefined local_2aa [2];
  undefined4 local_2a8 [5];
  undefined local_292 [602];
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  
  uVar5 = FUN_80286838();
  iVar1 = (int)uVar5;
  if (iVar1 == 1) {
    DAT_80315a28 = 0x1130;
  }
  else {
    DAT_80315a28 = 100;
  }
  local_322 = 0;
  local_324 = 0xe;
  local_328 = &DAT_803159f4;
  local_338 = 4;
  local_334 = FLOAT_803e19b8;
  local_330 = FLOAT_803e19b8;
  local_32c = FLOAT_803e19b8;
  if (iVar1 == 1) {
    local_30a = 0;
    local_30c = 0xe;
    local_310 = &DAT_803159f4;
    local_320 = 2;
    local_31c = FLOAT_803e19bc;
    local_318 = FLOAT_803e19bc;
  }
  else {
    local_30a = 0;
    local_30c = 0xe;
    local_310 = &DAT_803159f4;
    local_320 = 2;
    local_31c = FLOAT_803e19bc;
    uStack_34 = FUN_80022264(3,5);
    uStack_34 = uStack_34 ^ 0x80000000;
    local_38 = 0x43300000;
    local_318 = FLOAT_803e19c0 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e1a00);
  }
  local_2f2 = 0;
  local_2f4 = 0xe;
  local_2f8 = &DAT_803159f4;
  local_308 = 0x80;
  local_304 = FLOAT_803e19b8;
  local_300 = FLOAT_803e19b8;
  local_2fc = FLOAT_803e19c4;
  local_314 = FLOAT_803e19bc;
  if (iVar1 == 1) {
    local_2da = 0;
    local_2dc = 0xe;
    local_2e0 = &DAT_803159f4;
    local_2f0 = 0x400000;
    local_2ec = FLOAT_803e19c8;
    local_2e8 = FLOAT_803e19cc;
    local_2e4 = FLOAT_803e19b8;
    local_2c2[0] = 0;
    local_2c4 = 400;
    local_2c8 = 0;
    local_2d8 = 0x20000000;
    local_2d4 = FLOAT_803e19d0;
    local_2d0 = FLOAT_803e19d4;
    local_2cc = FLOAT_803e19d8;
    local_2aa[0] = 0;
    local_2ac = 0;
    local_2b0 = 0;
    local_2c0 = 0x80000;
    local_2bc = FLOAT_803e19dc;
    local_2b8 = FLOAT_803e19e0;
    local_2b4 = FLOAT_803e19b8;
    puVar4 = (undefined4 *)(local_2aa + 2);
  }
  else {
    local_2da = 0;
    local_2dc = 0xe;
    local_2e0 = &DAT_803159f4;
    local_2f0 = 0x400000;
    uStack_34 = FUN_80022264(0,0x14);
    uStack_34 = uStack_34 ^ 0x80000000;
    local_38 = 0x43300000;
    local_2ec = FLOAT_803e19e4 + (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e1a00);
    local_2e8 = FLOAT_803e19cc;
    uStack_2c = FUN_80022264(0,0x1e);
    uStack_2c = uStack_2c ^ 0x80000000;
    local_30 = 0x43300000;
    local_2e4 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e1a00);
    puVar4 = &local_2d8;
  }
  *(undefined *)((int)puVar4 + 0x16) = 1;
  *(undefined2 *)(puVar4 + 5) = 10;
  puVar4[4] = &DAT_80315a10;
  *puVar4 = 4;
  puVar4[1] = FLOAT_803e19e8;
  puVar4[2] = FLOAT_803e19b8;
  puVar4[3] = FLOAT_803e19b8;
  *(undefined *)((int)puVar4 + 0x2e) = 1;
  *(undefined2 *)(puVar4 + 0xb) = 0xe;
  puVar4[10] = &DAT_803159f4;
  puVar4[6] = 2;
  puVar4[7] = FLOAT_803e19bc;
  puVar4[8] = FLOAT_803e19bc;
  puVar4[9] = FLOAT_803e19bc;
  puVar3 = puVar4 + 0xc;
  if (iVar1 != 1) {
    *(undefined *)((int)puVar4 + 0x46) = 2;
    *(undefined2 *)(puVar4 + 0x11) = 0xe;
    puVar4[0x10] = &DAT_803159f4;
    *puVar3 = 0x400000;
    uStack_2c = FUN_80022264(1,0x28);
    uStack_2c = uStack_2c ^ 0x80000000;
    local_30 = 0x43300000;
    puVar4[0xd] = FLOAT_803e19ec * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e1a00)
    ;
    puVar4[0xe] = FLOAT_803e19b8;
    puVar4[0xf] = FLOAT_803e19b8;
    puVar3 = puVar4 + 0x12;
  }
  *(undefined *)((int)puVar3 + 0x16) = 2;
  *(undefined2 *)(puVar3 + 5) = 0xe;
  puVar3[4] = &DAT_803159f4;
  *puVar3 = 0x4000;
  uStack_2c = FUN_80022264(0xfffffffd,3);
  uStack_2c = uStack_2c ^ 0x80000000;
  local_30 = 0x43300000;
  puVar3[1] = FLOAT_803e19f0 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e1a00);
  puVar3[2] = FLOAT_803e19b8;
  puVar3[3] = FLOAT_803e19b8;
  *(undefined *)((int)puVar3 + 0x2e) = 3;
  *(undefined2 *)(puVar3 + 0xb) = 0xe;
  puVar3[10] = &DAT_803159f4;
  puVar3[6] = 0x4000;
  puVar3[7] = FLOAT_803e19f4;
  puVar3[8] = FLOAT_803e19b8;
  puVar3[9] = FLOAT_803e19b8;
  *(undefined *)((int)puVar3 + 0x46) = 3;
  *(undefined2 *)(puVar3 + 0x11) = 10;
  puVar3[0x10] = &DAT_80315a10;
  puVar3[0xc] = 4;
  puVar3[0xd] = FLOAT_803e19b8;
  puVar3[0xe] = FLOAT_803e19b8;
  puVar3[0xf] = FLOAT_803e19b8;
  puVar4 = puVar3 + 0x12;
  if (iVar1 == 1) {
    *(undefined *)((int)puVar3 + 0x5e) = 3;
    *(undefined2 *)(puVar3 + 0x17) = 0;
    puVar3[0x16] = 0;
    *puVar4 = 0x20000000;
    puVar3[0x13] = FLOAT_803e19d0;
    puVar3[0x14] = FLOAT_803e19d4;
    puVar3[0x15] = FLOAT_803e19d8;
    puVar4 = puVar3 + 0x18;
  }
  local_340 = 0;
  local_354 = (undefined2)uVar5;
  local_36c = FLOAT_803e19b8;
  local_368 = FLOAT_803e19f8;
  local_364 = FLOAT_803e19b8;
  local_378 = FLOAT_803e19b8;
  local_374 = FLOAT_803e19b8;
  local_370 = FLOAT_803e19b8;
  local_360 = FLOAT_803e19bc;
  local_358 = 1;
  local_35c = 0;
  local_33f = 0xe;
  local_33e = 0;
  local_394 = (int)((ulonglong)uVar5 >> 0x20);
  uVar2 = FUN_80022264(0x18,0x1c);
  local_33d = (undefined)uVar2;
  iVar1 = ((int)puVar4 - (int)&local_338) / 0x18 + ((int)puVar4 - (int)&local_338 >> 0x1f);
  local_33b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_352 = DAT_80315a24;
  local_350 = DAT_80315a26;
  local_34e = DAT_80315a28;
  local_34c = DAT_80315a2a;
  local_34a = DAT_80315a2c;
  local_348 = DAT_80315a2e;
  local_346 = DAT_80315a30;
  local_398 = &local_338;
  local_344 = param_4 | 0x1000000;
  if ((param_4 & 1) != 0) {
    if (local_394 == 0) {
      local_36c = local_36c + *(float *)(param_3 + 0xc);
      local_368 = local_368 + *(float *)(param_3 + 0x10);
      local_364 = local_364 + *(float *)(param_3 + 0x14);
    }
    else {
      local_36c = local_36c + *(float *)(local_394 + 0x18);
      local_368 = local_368 + *(float *)(local_394 + 0x1c);
      local_364 = local_364 + *(float *)(local_394 + 0x20);
    }
  }
  (**(code **)(*DAT_803dd6fc + 8))(&local_398,0,0xe,&DAT_80315900,0xc,&DAT_8031598c,0x8e,0);
  FUN_80286884();
  return;
}

