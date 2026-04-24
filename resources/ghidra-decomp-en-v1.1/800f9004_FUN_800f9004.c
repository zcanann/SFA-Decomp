// Function: FUN_800f9004
// Entry: 800f9004
// Size: 2572 bytes

void FUN_800f9004(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  undefined8 uVar6;
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
  undefined4 local_318;
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
  undefined4 local_2c8;
  float local_2c4;
  float local_2c0;
  float local_2bc;
  undefined *local_2b8;
  undefined2 local_2b4;
  undefined local_2b2;
  undefined4 local_2b0 [162];
  undefined4 local_28;
  uint uStack_24;
  
  uVar6 = FUN_80286834();
  iVar2 = (int)((ulonglong)uVar6 >> 0x20);
  iVar3 = (int)uVar6;
  if (iVar3 == 0) {
    local_312[0] = 0;
    local_314 = 0x8c;
    local_318 = 0;
    local_328 = 0x20000000;
    local_324 = FLOAT_803e1d60;
    local_320 = FLOAT_803e1d64;
    local_31c = FLOAT_803e1d68;
    local_2fa[0] = 0;
    local_2fc = 9;
    local_300 = &DAT_8031783c;
    local_310 = 0x80;
    if (param_3 == 0) {
      local_30c = FLOAT_803e1d6c;
      local_308 = FLOAT_803e1d70;
      local_304 = FLOAT_803e1d6c;
    }
    else {
      local_30c = *(float *)(param_3 + 0xc);
      local_308 = *(float *)(param_3 + 0x10);
      local_304 = *(float *)(param_3 + 0x14);
    }
    local_2e2[0] = 0;
    local_2e4 = 8;
    local_2e8 = &DAT_8031783c;
    local_2f8 = 2;
    local_2f4 = FLOAT_803e1d74;
    local_2f0 = FLOAT_803e1d74;
    local_2ec = FLOAT_803e1d78;
    puVar4 = &local_2e0;
  }
  else if (iVar3 == 1) {
    DAT_80317862 = 0x50;
    DAT_80317864 = 0x50;
    local_312[0] = 0;
    local_314 = 2;
    local_318 = 0;
    local_328 = 0x1800000;
    local_324 = FLOAT_803e1d7c;
    local_320 = FLOAT_803e1d6c;
    local_31c = FLOAT_803e1d6c;
    local_2fa[0] = 0;
    local_2fc = 0x69;
    local_300 = (undefined *)0x0;
    local_310 = 0x1800000;
    local_30c = FLOAT_803e1d7c;
    local_308 = FLOAT_803e1d6c;
    local_304 = FLOAT_803e1d6c;
    local_2e2[0] = 0;
    local_2e4 = 8;
    local_2e8 = &DAT_8031783c;
    local_2f8 = 2;
    uStack_24 = FUN_80022264(0,0xc);
    uStack_24 = uStack_24 ^ 0x80000000;
    local_28 = 0x43300000;
    local_2ec = FLOAT_803e1d80 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e1db0);
    local_2f4 = FLOAT_803e1d84 + local_2ec;
    local_2ec = FLOAT_803e1d88 + local_2ec;
    local_2ca = 0;
    local_2cc = 0x8c;
    local_2d0 = (undefined *)0x0;
    local_2e0 = 0x20000000;
    local_2dc = FLOAT_803e1d60;
    local_2d8 = FLOAT_803e1d8c;
    local_2d4 = FLOAT_803e1d90;
    local_2b2 = 0;
    local_2b4 = 9;
    local_2b8 = &DAT_8031783c;
    local_2c8 = 0x80;
    local_2f0 = local_2f4;
    if (param_3 == 0) {
      local_2c4 = FLOAT_803e1d6c;
      local_2c0 = FLOAT_803e1d70;
      local_2bc = FLOAT_803e1d6c;
      puVar4 = local_2b0;
    }
    else {
      local_2c4 = *(float *)(param_3 + 0xc);
      local_2c0 = *(float *)(param_3 + 0x10);
      local_2bc = *(float *)(param_3 + 0x14);
      puVar4 = local_2b0;
    }
  }
  else {
    puVar4 = &local_328;
    if (iVar3 == 2) {
      DAT_80317862 = 0x50;
      DAT_80317864 = 0x50;
      local_312[0] = 0;
      local_314 = 0x1fc;
      local_318 = 0;
      local_328 = 0x1800000;
      local_324 = FLOAT_803e1d7c;
      local_320 = FLOAT_803e1d6c;
      local_31c = FLOAT_803e1d6c;
      local_2fa[0] = 0;
      local_2fc = 8;
      local_300 = &DAT_8031783c;
      local_310 = 2;
      uStack_24 = FUN_80022264(0,0xc);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_304 = FLOAT_803e1d80 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e1db0)
      ;
      local_30c = FLOAT_803e1d94 + local_304;
      local_304 = FLOAT_803e1d98 + local_304;
      local_2e2[0] = 0;
      local_2e4 = 0x8c;
      local_2e8 = (undefined *)0x0;
      local_2f8 = 0x20000000;
      local_2f4 = FLOAT_803e1d60;
      local_2f0 = FLOAT_803e1d8c;
      local_2ec = FLOAT_803e1d90;
      local_2ca = 0;
      local_2cc = 9;
      local_2d0 = &DAT_8031783c;
      local_2e0 = 0x80;
      local_308 = local_30c;
      if (param_3 == 0) {
        local_2dc = FLOAT_803e1d6c;
        local_2d8 = FLOAT_803e1d70;
        local_2d4 = FLOAT_803e1d6c;
        puVar4 = &local_2c8;
      }
      else {
        local_2dc = *(float *)(param_3 + 0xc);
        local_2d8 = *(float *)(param_3 + 0x10);
        local_2d4 = *(float *)(param_3 + 0x14);
        puVar4 = &local_2c8;
      }
    }
  }
  if (iVar3 == 0) {
    *(undefined *)((int)puVar4 + 0x16) = 1;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = &DAT_8031783c;
    *puVar4 = 0x4000;
    puVar4[1] = FLOAT_803e1d6c;
    puVar4[2] = FLOAT_803e1d6c;
    puVar4[3] = FLOAT_803e1d6c;
    *(undefined *)((int)puVar4 + 0x2e) = 1;
    *(undefined2 *)(puVar4 + 0xb) = 0x68;
    puVar4[10] = 0;
    puVar4[6] = 0x800000;
    puVar4[7] = FLOAT_803e1d7c;
    puVar4[8] = FLOAT_803e1d6c;
    puVar4[9] = FLOAT_803e1d6c;
    *(undefined *)((int)puVar4 + 0x46) = 1;
    *(undefined2 *)(puVar4 + 0x11) = 8;
    puVar4[0x10] = &DAT_8031783c;
    puVar4[0xc] = 2;
    puVar4[0xd] = FLOAT_803e1d9c;
    puVar4[0xe] = FLOAT_803e1d9c;
    puVar4[0xf] = FLOAT_803e1d9c;
    puVar4 = puVar4 + 0x12;
  }
  else if (iVar3 == 1) {
    *(undefined *)((int)puVar4 + 0x16) = 1;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = &DAT_8031783c;
    *puVar4 = 0x4000;
    puVar4[1] = FLOAT_803e1d6c;
    puVar4[2] = FLOAT_803e1d6c;
    puVar4[3] = FLOAT_803e1d6c;
    *(undefined *)((int)puVar4 + 0x2e) = 1;
    *(undefined2 *)(puVar4 + 0xb) = 0x8f;
    puVar4[10] = 0;
    puVar4[6] = 0x1800000;
    puVar4[7] = FLOAT_803e1da0;
    puVar4[8] = FLOAT_803e1d6c;
    puVar4[9] = FLOAT_803e1d6c;
    puVar4 = puVar4 + 0xc;
  }
  else if (iVar3 == 2) {
    *(undefined *)((int)puVar4 + 0x16) = 1;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = &DAT_8031783c;
    *puVar4 = 0x4000;
    puVar4[1] = FLOAT_803e1d6c;
    puVar4[2] = FLOAT_803e1d6c;
    puVar4[3] = FLOAT_803e1d6c;
    *(undefined *)((int)puVar4 + 0x2e) = 1;
    *(undefined2 *)(puVar4 + 0xb) = 0x1fd;
    puVar4[10] = 0;
    puVar4[6] = 0x1800000;
    puVar4[7] = FLOAT_803e1da0;
    puVar4[8] = FLOAT_803e1d6c;
    puVar4[9] = FLOAT_803e1d6c;
    puVar4 = puVar4 + 0xc;
  }
  if (iVar3 == 0) {
    *(undefined *)((int)puVar4 + 0x16) = 1;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = &DAT_8031783c;
    *puVar4 = 0x100;
    puVar4[1] = FLOAT_803e1da4;
    puVar4[2] = FLOAT_803e1d6c;
    puVar4[3] = FLOAT_803e1d6c;
    puVar4 = puVar4 + 6;
  }
  else if (iVar3 == 1) {
    *(undefined *)((int)puVar4 + 0x16) = 1;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = &DAT_8031783c;
    *puVar4 = 0x100;
    puVar4[1] = FLOAT_803e1da8;
    puVar4[2] = FLOAT_803e1d6c;
    puVar4[3] = FLOAT_803e1d6c;
    puVar4 = puVar4 + 6;
  }
  else if (iVar3 == 2) {
    *(undefined *)((int)puVar4 + 0x16) = 1;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = &DAT_8031783c;
    *puVar4 = 0x100;
    puVar4[1] = FLOAT_803e1da8;
    puVar4[2] = FLOAT_803e1d6c;
    puVar4[3] = FLOAT_803e1d6c;
    puVar4 = puVar4 + 6;
  }
  if (iVar3 == 0) {
    *(undefined *)((int)puVar4 + 0x16) = 2;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = &DAT_8031783c;
    *puVar4 = 0x100;
    puVar4[1] = FLOAT_803e1da4;
    puVar4[2] = FLOAT_803e1d6c;
    puVar4[3] = FLOAT_803e1d6c;
    puVar4 = puVar4 + 6;
  }
  else if (iVar3 == 1) {
    *(undefined *)((int)puVar4 + 0x16) = 2;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = &DAT_8031783c;
    *puVar4 = 0x100;
    puVar4[1] = FLOAT_803e1da8;
    puVar4[2] = FLOAT_803e1d6c;
    puVar4[3] = FLOAT_803e1d6c;
    puVar4 = puVar4 + 6;
  }
  else if (iVar3 == 2) {
    *(undefined *)((int)puVar4 + 0x16) = 2;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = &DAT_8031783c;
    *puVar4 = 0x100;
    puVar4[1] = FLOAT_803e1da8;
    puVar4[2] = FLOAT_803e1d6c;
    puVar4[3] = FLOAT_803e1d6c;
    puVar4 = puVar4 + 6;
  }
  *(undefined *)((int)puVar4 + 0x16) = 2;
  *(undefined2 *)(puVar4 + 5) = 9;
  puVar4[4] = &DAT_8031783c;
  *puVar4 = 4;
  puVar4[1] = FLOAT_803e1d6c;
  puVar4[2] = FLOAT_803e1d6c;
  puVar4[3] = FLOAT_803e1d6c;
  puVar5 = puVar4 + 6;
  if (iVar3 == 0) {
    *(undefined *)((int)puVar4 + 0x2e) = 3;
    *(undefined2 *)(puVar4 + 0xb) = 0;
    puVar4[10] = 0;
    *puVar5 = 0x20000000;
    puVar4[7] = FLOAT_803e1d60;
    puVar4[8] = FLOAT_803e1d64;
    puVar4[9] = FLOAT_803e1d68;
    puVar5 = puVar4 + 0xc;
  }
  else if (iVar3 == 1) {
    *(undefined *)((int)puVar4 + 0x2e) = 3;
    *(undefined2 *)(puVar4 + 0xb) = 0;
    puVar4[10] = 0;
    *puVar5 = 0x20000000;
    puVar4[7] = FLOAT_803e1d60;
    puVar4[8] = FLOAT_803e1d8c;
    puVar4[9] = FLOAT_803e1d90;
    puVar5 = puVar4 + 0xc;
  }
  else if (iVar3 == 2) {
    *(undefined *)((int)puVar4 + 0x2e) = 3;
    *(undefined2 *)(puVar4 + 0xb) = 0;
    puVar4[10] = 0;
    *puVar5 = 0x20000000;
    puVar4[7] = FLOAT_803e1d60;
    puVar4[8] = FLOAT_803e1d8c;
    puVar4[9] = FLOAT_803e1d90;
    puVar5 = puVar4 + 0xc;
  }
  local_344 = (undefined2)uVar6;
  local_35c = FLOAT_803e1d6c;
  local_368 = FLOAT_803e1d6c;
  local_364 = FLOAT_803e1d6c;
  local_360 = FLOAT_803e1d6c;
  local_350 = FLOAT_803e1d7c;
  local_348 = 1;
  local_34c = 0;
  local_32f = 9;
  local_32e = 0;
  local_32d = 0;
  iVar1 = (int)puVar5 - (int)&local_328;
  iVar1 = iVar1 / 0x18 + (iVar1 >> 0x1f);
  local_32b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_342 = DAT_80317860;
  local_340 = DAT_80317862;
  local_33e = DAT_80317864;
  local_33c = DAT_80317866;
  local_33a = DAT_80317868;
  local_338 = DAT_8031786a;
  local_336 = DAT_8031786c;
  local_388 = &local_328;
  local_334 = param_4 | 0x4000000;
  local_358 = local_35c;
  local_354 = local_35c;
  if ((param_4 & 1) != 0) {
    if (iVar2 == 0) {
      local_35c = FLOAT_803e1d6c + *(float *)(param_3 + 0xc);
      local_358 = FLOAT_803e1d6c + *(float *)(param_3 + 0x10);
      local_354 = FLOAT_803e1d6c + *(float *)(param_3 + 0x14);
    }
    else {
      local_35c = FLOAT_803e1d6c + *(float *)(iVar2 + 0x18);
      local_358 = FLOAT_803e1d6c + *(float *)(iVar2 + 0x1c);
      local_354 = FLOAT_803e1d6c + *(float *)(iVar2 + 0x20);
    }
  }
  local_384 = iVar2;
  if (iVar3 == 0) {
    local_330 = 0;
    (**(code **)(*DAT_803dd6fc + 8))(&local_388,0,9,&DAT_803177b0,8,&DAT_8031780c,0x156,0);
  }
  else if (iVar3 == 1) {
    local_330 = 0;
    local_334 = param_4 | 0x4000004;
    (**(code **)(*DAT_803dd6fc + 8))(&local_388,0,9,&DAT_803177b0,8,&DAT_8031780c,0xc0d,0);
  }
  else if (iVar3 == 2) {
    local_330 = 0;
    local_334 = param_4 | 0x4000004;
    (**(code **)(*DAT_803dd6fc + 8))(&local_388,0,9,&DAT_803177b0,8,&DAT_8031780c,0x23b,0);
  }
  FUN_80286880();
  return;
}

