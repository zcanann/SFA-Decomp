// Function: FUN_800f369c
// Entry: 800f369c
// Size: 2248 bytes

void FUN_800f369c(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined4 *puVar4;
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
  char local_32b;
  undefined4 local_328;
  float local_324;
  float local_320;
  float local_31c;
  undefined *local_318;
  undefined2 local_314;
  undefined local_312 [2];
  undefined4 local_310;
  float local_30c;
  float local_308;
  float local_304;
  undefined *local_300;
  undefined2 local_2fc;
  undefined local_2fa [2];
  undefined4 local_2f8;
  float local_2f4;
  float local_2f0;
  float local_2ec;
  undefined *local_2e8;
  undefined2 local_2e4;
  undefined local_2e2 [2];
  undefined4 local_2e0;
  float local_2dc;
  float local_2d8;
  float local_2d4;
  undefined *local_2d0;
  undefined2 local_2cc;
  undefined local_2ca;
  undefined4 local_2c8 [168];
  undefined4 local_28;
  uint uStack_24;
  
  uVar5 = FUN_80286834();
  iVar2 = (int)((ulonglong)uVar5 >> 0x20);
  iVar3 = (int)uVar5;
  if (iVar3 == 0) {
    local_312[0] = 0;
    local_314 = 9;
    local_318 = &DAT_803157cc;
    local_328 = 0x80;
    local_324 = FLOAT_803e1930;
    local_320 = FLOAT_803e1930;
    local_31c = FLOAT_803e1934;
    local_2fa[0] = 0;
    local_2fc = 8;
    local_300 = &DAT_803157cc;
    local_310 = 2;
    local_30c = FLOAT_803e1938;
    local_308 = FLOAT_803e1938;
    local_304 = FLOAT_803e193c;
    puVar4 = &local_2f8;
  }
  else if (iVar3 == 1) {
    DAT_803157f2 = 0x50;
    DAT_803157f4 = 0x118;
    local_312[0] = 0;
    local_314 = 0x69;
    local_318 = (undefined *)0x0;
    local_328 = 0x1800000;
    local_324 = FLOAT_803e1940;
    local_320 = FLOAT_803e1930;
    local_31c = FLOAT_803e1930;
    local_2fa[0] = 0;
    local_2fc = 8;
    local_300 = &DAT_803157cc;
    local_310 = 2;
    uStack_24 = FUN_80022264(0,0xc);
    uStack_24 = uStack_24 ^ 0x80000000;
    local_28 = 0x43300000;
    local_304 = FLOAT_803e1944 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e1980);
    local_30c = FLOAT_803e1948 + local_304;
    local_304 = FLOAT_803e194c + local_304;
    local_2e2[0] = 0;
    local_2e4 = 9;
    local_2e8 = &DAT_803157cc;
    local_2f8 = 0x80;
    local_2f4 = FLOAT_803e1930;
    local_2f0 = FLOAT_803e1930;
    local_2ec = FLOAT_803e1950;
    local_2ca = 0;
    local_2cc = 8;
    local_2d0 = &DAT_803157e0;
    local_2e0 = 4;
    local_2dc = FLOAT_803e1954;
    local_2d8 = FLOAT_803e1930;
    local_2d4 = FLOAT_803e1930;
    puVar4 = local_2c8;
    local_308 = local_30c;
  }
  else {
    puVar4 = &local_328;
    if (iVar3 == 2) {
      DAT_803157f2 = 0x50;
      DAT_803157f4 = 0x50;
      local_312[0] = 0;
      local_314 = 0x1fc;
      local_318 = (undefined *)0x0;
      local_328 = 0x1800000;
      local_324 = FLOAT_803e1940;
      local_320 = FLOAT_803e1930;
      local_31c = FLOAT_803e1930;
      local_2fa[0] = 0;
      local_2fc = 8;
      local_300 = &DAT_803157cc;
      local_310 = 2;
      uStack_24 = FUN_80022264(0,0xc);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_304 = FLOAT_803e1944 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e1980)
      ;
      local_30c = FLOAT_803e1958 + local_304;
      local_304 = FLOAT_803e195c + local_304;
      local_2e2[0] = 0;
      local_2e4 = 0x8c;
      local_2e8 = (undefined *)0x0;
      local_2f8 = 0x20000000;
      local_2f4 = FLOAT_803e1960;
      local_2f0 = FLOAT_803e1964;
      local_2ec = FLOAT_803e1968;
      local_2ca = 0;
      local_2cc = 9;
      local_2d0 = &DAT_803157cc;
      local_2e0 = 0x80;
      local_2dc = FLOAT_803e1930;
      local_2d8 = FLOAT_803e1930;
      local_2d4 = FLOAT_803e1950;
      puVar4 = local_2c8;
      local_308 = local_30c;
    }
  }
  if (iVar3 == 0) {
    *(undefined *)((int)puVar4 + 0x16) = 1;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = &DAT_803157cc;
    *puVar4 = 0x4000;
    puVar4[1] = FLOAT_803e1930;
    puVar4[2] = FLOAT_803e1930;
    puVar4[3] = FLOAT_803e1930;
    *(undefined *)((int)puVar4 + 0x2e) = 1;
    *(undefined2 *)(puVar4 + 0xb) = 8;
    puVar4[10] = &DAT_803157cc;
    puVar4[6] = 2;
    puVar4[7] = FLOAT_803e196c;
    puVar4[8] = FLOAT_803e196c;
    puVar4[9] = FLOAT_803e196c;
    puVar4 = puVar4 + 0xc;
  }
  else if (iVar3 == 1) {
    *(undefined *)((int)puVar4 + 0x16) = 1;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = &DAT_803157cc;
    *puVar4 = 0x4000;
    puVar4[1] = FLOAT_803e1930;
    puVar4[2] = FLOAT_803e1970;
    puVar4[3] = FLOAT_803e1930;
    *(undefined *)((int)puVar4 + 0x2e) = 1;
    *(undefined2 *)(puVar4 + 0xb) = 0x8f;
    puVar4[10] = 0;
    puVar4[6] = 0x1800000;
    puVar4[7] = FLOAT_803e195c;
    puVar4[8] = FLOAT_803e1930;
    puVar4[9] = FLOAT_803e1930;
    *(undefined *)((int)puVar4 + 0x46) = 0;
    *(undefined2 *)(puVar4 + 0x11) = 4;
    puVar4[0x10] = &DAT_803dc538;
    puVar4[0xc] = 2;
    puVar4[0xd] = FLOAT_803e1940;
    puVar4[0xe] = FLOAT_803e1940;
    puVar4[0xf] = FLOAT_803e1974;
    puVar4 = puVar4 + 0x12;
  }
  else if (iVar3 == 2) {
    *(undefined *)((int)puVar4 + 0x16) = 1;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = &DAT_803157cc;
    *puVar4 = 0x4000;
    puVar4[1] = FLOAT_803e1930;
    puVar4[2] = FLOAT_803e1930;
    puVar4[3] = FLOAT_803e1930;
    *(undefined *)((int)puVar4 + 0x2e) = 1;
    *(undefined2 *)(puVar4 + 0xb) = 0x1fd;
    puVar4[10] = 0;
    puVar4[6] = 0x1800000;
    puVar4[7] = FLOAT_803e1974;
    puVar4[8] = FLOAT_803e1930;
    puVar4[9] = FLOAT_803e1930;
    puVar4 = puVar4 + 0xc;
  }
  if (iVar3 == 0) {
    *(undefined *)((int)puVar4 + 0x16) = 1;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = &DAT_803157cc;
    *puVar4 = 0x100;
    puVar4[1] = FLOAT_803e1978;
    puVar4[2] = FLOAT_803e1930;
    puVar4[3] = FLOAT_803e1930;
    puVar4 = puVar4 + 6;
  }
  else if (iVar3 == 1) {
    *(undefined *)((int)puVar4 + 0x16) = 1;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = &DAT_803157cc;
    *puVar4 = 0x100;
    puVar4[1] = FLOAT_803e197c;
    puVar4[2] = FLOAT_803e1930;
    puVar4[3] = FLOAT_803e1930;
    puVar4 = puVar4 + 6;
  }
  else if (iVar3 == 2) {
    *(undefined *)((int)puVar4 + 0x16) = 1;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = &DAT_803157cc;
    *puVar4 = 0x100;
    puVar4[1] = FLOAT_803e197c;
    puVar4[2] = FLOAT_803e1930;
    puVar4[3] = FLOAT_803e1930;
    puVar4 = puVar4 + 6;
  }
  if (iVar3 == 0) {
    *(undefined *)((int)puVar4 + 0x16) = 2;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = &DAT_803157cc;
    *puVar4 = 0x100;
    puVar4[1] = FLOAT_803e1978;
    puVar4[2] = FLOAT_803e1930;
    puVar4[3] = FLOAT_803e1930;
    *(undefined *)((int)puVar4 + 0x2e) = 2;
    *(undefined2 *)(puVar4 + 0xb) = 9;
    puVar4[10] = &DAT_803157cc;
    puVar4[6] = 4;
    puVar4[7] = FLOAT_803e1930;
    puVar4[8] = FLOAT_803e1930;
    puVar4[9] = FLOAT_803e1930;
    puVar4 = puVar4 + 0xc;
  }
  else if (iVar3 == 1) {
    *(undefined *)((int)puVar4 + 0x16) = 2;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = &DAT_803157cc;
    *puVar4 = 0x100;
    puVar4[1] = FLOAT_803e197c;
    puVar4[2] = FLOAT_803e1930;
    puVar4[3] = FLOAT_803e1930;
    puVar4 = puVar4 + 6;
  }
  else if (iVar3 == 2) {
    *(undefined *)((int)puVar4 + 0x16) = 2;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = &DAT_803157cc;
    *puVar4 = 0x100;
    puVar4[1] = FLOAT_803e197c;
    puVar4[2] = FLOAT_803e1930;
    puVar4[3] = FLOAT_803e1930;
    *(undefined *)((int)puVar4 + 0x2e) = 2;
    *(undefined2 *)(puVar4 + 0xb) = 9;
    puVar4[10] = &DAT_803157cc;
    puVar4[6] = 4;
    puVar4[7] = FLOAT_803e1930;
    puVar4[8] = FLOAT_803e1930;
    puVar4[9] = FLOAT_803e1930;
    puVar4 = puVar4 + 0xc;
  }
  if (iVar3 == 2) {
    *(undefined *)((int)puVar4 + 0x16) = 3;
    *(undefined2 *)(puVar4 + 5) = 0;
    puVar4[4] = 0;
    *puVar4 = 0x20000000;
    puVar4[1] = FLOAT_803e1960;
    puVar4[2] = FLOAT_803e1964;
    puVar4[3] = FLOAT_803e1968;
    puVar4 = puVar4 + 6;
  }
  local_344 = (undefined2)uVar5;
  local_35c = FLOAT_803e1930;
  local_368 = FLOAT_803e1930;
  local_364 = FLOAT_803e1930;
  local_360 = FLOAT_803e1930;
  local_350 = FLOAT_803e1940;
  local_348 = 1;
  local_34c = 0;
  local_32f = 9;
  local_32e = 0;
  local_32d = 0;
  iVar1 = (int)puVar4 - (int)&local_328;
  iVar1 = iVar1 / 0x18 + (iVar1 >> 0x1f);
  local_32b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_342 = DAT_803157f0;
  local_340 = DAT_803157f2;
  local_33e = DAT_803157f4;
  local_33c = DAT_803157f6;
  local_33a = DAT_803157f8;
  local_338 = DAT_803157fa;
  local_336 = DAT_803157fc;
  local_388 = &local_328;
  local_334 = param_4 | 0x4000000;
  local_358 = local_35c;
  local_354 = local_35c;
  if ((param_4 & 1) != 0) {
    if (iVar2 == 0) {
      local_35c = FLOAT_803e1930 + *(float *)(param_3 + 0xc);
      local_358 = FLOAT_803e1930 + *(float *)(param_3 + 0x10);
      local_354 = FLOAT_803e1930 + *(float *)(param_3 + 0x14);
    }
    else {
      local_35c = FLOAT_803e1930 + *(float *)(iVar2 + 0x18);
      local_358 = FLOAT_803e1930 + *(float *)(iVar2 + 0x1c);
      local_354 = FLOAT_803e1930 + *(float *)(iVar2 + 0x20);
    }
  }
  local_384 = iVar2;
  if (iVar3 == 0) {
    local_330 = 0;
    (**(code **)(*DAT_803dd6fc + 8))(&local_388,0,9,&DAT_80315740,8,&DAT_8031579c,0x156,0);
  }
  else if (iVar3 == 1) {
    local_330 = 0;
    local_334 = param_4 | 0x4000004;
    (**(code **)(*DAT_803dd6fc + 8))(&local_388,0,9,&DAT_80315740,8,&DAT_8031579c,0x89,0);
  }
  else if (iVar3 == 2) {
    local_330 = 0;
    local_334 = param_4 | 0x4000004;
    (**(code **)(*DAT_803dd6fc + 8))(&local_388,0,9,&DAT_80315740,8,&DAT_8031579c,0x23b,0);
  }
  FUN_80286880();
  return;
}

