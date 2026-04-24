// Function: FUN_800f4174
// Entry: 800f4174
// Size: 1456 bytes

void FUN_800f4174(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  undefined8 uVar4;
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
  uint uStack52;
  undefined4 local_30;
  uint uStack44;
  
  uVar4 = FUN_802860d4();
  local_394 = (int)((ulonglong)uVar4 >> 0x20);
  iVar1 = (int)uVar4;
  if (iVar1 == 1) {
    DAT_80314dd8 = 0x1130;
  }
  else {
    DAT_80314dd8 = 100;
  }
  local_322 = 0;
  local_324 = 0xe;
  local_328 = &DAT_80314da4;
  local_338 = 4;
  local_334 = FLOAT_803e0d38;
  local_330 = FLOAT_803e0d38;
  local_32c = FLOAT_803e0d38;
  if (iVar1 == 1) {
    local_30a = 0;
    local_30c = 0xe;
    local_310 = &DAT_80314da4;
    local_320 = 2;
    local_31c = FLOAT_803e0d3c;
    local_318 = FLOAT_803e0d3c;
  }
  else {
    local_30a = 0;
    local_30c = 0xe;
    local_310 = &DAT_80314da4;
    local_320 = 2;
    local_31c = FLOAT_803e0d3c;
    uStack52 = FUN_800221a0(3,5);
    uStack52 = uStack52 ^ 0x80000000;
    local_38 = 0x43300000;
    local_318 = FLOAT_803e0d40 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e0d80);
  }
  local_2f2 = 0;
  local_2f4 = 0xe;
  local_2f8 = &DAT_80314da4;
  local_308 = 0x80;
  local_304 = FLOAT_803e0d38;
  local_300 = FLOAT_803e0d38;
  local_2fc = FLOAT_803e0d44;
  local_314 = FLOAT_803e0d3c;
  if (iVar1 == 1) {
    local_2da = 0;
    local_2dc = 0xe;
    local_2e0 = &DAT_80314da4;
    local_2f0 = 0x400000;
    local_2ec = FLOAT_803e0d48;
    local_2e8 = FLOAT_803e0d4c;
    local_2e4 = FLOAT_803e0d38;
    local_2c2[0] = 0;
    local_2c4 = 400;
    local_2c8 = 0;
    local_2d8 = 0x20000000;
    local_2d4 = FLOAT_803e0d50;
    local_2d0 = FLOAT_803e0d54;
    local_2cc = FLOAT_803e0d58;
    local_2aa[0] = 0;
    local_2ac = 0;
    local_2b0 = 0;
    local_2c0 = 0x80000;
    local_2bc = FLOAT_803e0d5c;
    local_2b8 = FLOAT_803e0d60;
    local_2b4 = FLOAT_803e0d38;
    puVar3 = (undefined4 *)(local_2aa + 2);
  }
  else {
    local_2da = 0;
    local_2dc = 0xe;
    local_2e0 = &DAT_80314da4;
    local_2f0 = 0x400000;
    uStack52 = FUN_800221a0(0,0x14);
    uStack52 = uStack52 ^ 0x80000000;
    local_38 = 0x43300000;
    local_2ec = FLOAT_803e0d64 + (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e0d80);
    local_2e8 = FLOAT_803e0d4c;
    uStack44 = FUN_800221a0(0,0x1e);
    uStack44 = uStack44 ^ 0x80000000;
    local_30 = 0x43300000;
    local_2e4 = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e0d80);
    puVar3 = &local_2d8;
  }
  *(undefined *)((int)puVar3 + 0x16) = 1;
  *(undefined2 *)(puVar3 + 5) = 10;
  puVar3[4] = &DAT_80314dc0;
  *puVar3 = 4;
  puVar3[1] = FLOAT_803e0d68;
  puVar3[2] = FLOAT_803e0d38;
  puVar3[3] = FLOAT_803e0d38;
  *(undefined *)((int)puVar3 + 0x2e) = 1;
  *(undefined2 *)(puVar3 + 0xb) = 0xe;
  puVar3[10] = &DAT_80314da4;
  puVar3[6] = 2;
  puVar3[7] = FLOAT_803e0d3c;
  puVar3[8] = FLOAT_803e0d3c;
  puVar3[9] = FLOAT_803e0d3c;
  puVar2 = puVar3 + 0xc;
  if (iVar1 != 1) {
    *(undefined *)((int)puVar3 + 0x46) = 2;
    *(undefined2 *)(puVar3 + 0x11) = 0xe;
    puVar3[0x10] = &DAT_80314da4;
    *puVar2 = 0x400000;
    uStack44 = FUN_800221a0(1,0x28);
    uStack44 = uStack44 ^ 0x80000000;
    local_30 = 0x43300000;
    puVar3[0xd] = FLOAT_803e0d6c * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e0d80);
    puVar3[0xe] = FLOAT_803e0d38;
    puVar3[0xf] = FLOAT_803e0d38;
    puVar2 = puVar3 + 0x12;
  }
  *(undefined *)((int)puVar2 + 0x16) = 2;
  *(undefined2 *)(puVar2 + 5) = 0xe;
  puVar2[4] = &DAT_80314da4;
  *puVar2 = 0x4000;
  uStack44 = FUN_800221a0(0xfffffffd,3);
  uStack44 = uStack44 ^ 0x80000000;
  local_30 = 0x43300000;
  puVar2[1] = FLOAT_803e0d70 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e0d80);
  puVar2[2] = FLOAT_803e0d38;
  puVar2[3] = FLOAT_803e0d38;
  *(undefined *)((int)puVar2 + 0x2e) = 3;
  *(undefined2 *)(puVar2 + 0xb) = 0xe;
  puVar2[10] = &DAT_80314da4;
  puVar2[6] = 0x4000;
  puVar2[7] = FLOAT_803e0d74;
  puVar2[8] = FLOAT_803e0d38;
  puVar2[9] = FLOAT_803e0d38;
  *(undefined *)((int)puVar2 + 0x46) = 3;
  *(undefined2 *)(puVar2 + 0x11) = 10;
  puVar2[0x10] = &DAT_80314dc0;
  puVar2[0xc] = 4;
  puVar2[0xd] = FLOAT_803e0d38;
  puVar2[0xe] = FLOAT_803e0d38;
  puVar2[0xf] = FLOAT_803e0d38;
  puVar3 = puVar2 + 0x12;
  if (iVar1 == 1) {
    *(undefined *)((int)puVar2 + 0x5e) = 3;
    *(undefined2 *)(puVar2 + 0x17) = 0;
    puVar2[0x16] = 0;
    *puVar3 = 0x20000000;
    puVar2[0x13] = FLOAT_803e0d50;
    puVar2[0x14] = FLOAT_803e0d54;
    puVar2[0x15] = FLOAT_803e0d58;
    puVar3 = puVar2 + 0x18;
  }
  local_340 = 0;
  local_354 = (undefined2)uVar4;
  local_36c = FLOAT_803e0d38;
  local_368 = FLOAT_803e0d78;
  local_364 = FLOAT_803e0d38;
  local_378 = FLOAT_803e0d38;
  local_374 = FLOAT_803e0d38;
  local_370 = FLOAT_803e0d38;
  local_360 = FLOAT_803e0d3c;
  local_358 = 1;
  local_35c = 0;
  local_33f = 0xe;
  local_33e = 0;
  local_33d = FUN_800221a0(0x18,0x1c);
  iVar1 = ((int)puVar3 - (int)&local_338) / 0x18 + ((int)puVar3 - (int)&local_338 >> 0x1f);
  local_33b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_352 = DAT_80314dd4;
  local_350 = DAT_80314dd6;
  local_34e = DAT_80314dd8;
  local_34c = DAT_80314dda;
  local_34a = DAT_80314ddc;
  local_348 = DAT_80314dde;
  local_346 = DAT_80314de0;
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
  (**(code **)(*DAT_803dca7c + 8))(&local_398,0,0xe,&DAT_80314cb0,0xc,&DAT_80314d3c,0x8e,0);
  FUN_80286120();
  return;
}

