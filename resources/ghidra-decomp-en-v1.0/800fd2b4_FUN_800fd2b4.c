// Function: FUN_800fd2b4
// Entry: 800fd2b4
// Size: 1160 bytes

void FUN_800fd2b4(int param_1,int param_2,short *param_3,uint param_4)

{
  int iVar1;
  undefined4 *puVar2;
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
  undefined4 local_288;
  undefined2 local_284;
  undefined local_282 [2];
  undefined4 local_280 [5];
  undefined local_26a [578];
  undefined4 local_28;
  uint uStack36;
  undefined4 local_20;
  uint uStack28;
  undefined4 local_18;
  uint uStack20;
  
  local_312 = 0;
  local_314 = 0x15;
  local_318 = &DAT_80317fb0;
  local_328 = 4;
  local_324 = FLOAT_803e13c8;
  local_320 = FLOAT_803e13c8;
  local_31c = FLOAT_803e13c8;
  local_2fa = 0;
  local_2fc = 0x15;
  local_300 = &DAT_80317fb0;
  local_310 = 2;
  local_30c = FLOAT_803e13cc;
  local_308 = FLOAT_803e13d0;
  local_304 = FLOAT_803e13cc;
  if (param_2 == 1) {
    local_2f8 = 0x80;
    uStack36 = (int)param_3[2] ^ 0x80000000;
    local_28 = 0x43300000;
    local_2f4 = (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e13f0);
    uStack28 = (int)param_3[1] ^ 0x80000000;
    local_20 = 0x43300000;
    local_2f0 = (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e13f0);
    uStack20 = (int)*param_3 ^ 0x80000000;
    local_18 = 0x43300000;
    local_2ec = (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e13f0);
    local_2d8 = *(float *)(param_3 + 8) / FLOAT_803e13d4;
  }
  else {
    local_2f8 = 0x400000;
    local_2f4 = FLOAT_803e13c8;
    local_2f0 = FLOAT_803e13c8;
    local_2ec = FLOAT_803e13c8;
    local_2d8 = FLOAT_803e13d8;
  }
  local_2ca = 1;
  local_2cc = 0x15;
  local_2d0 = &DAT_80317fb0;
  local_2dc = FLOAT_803e13d4;
  local_2e0 = 2;
  local_2e2 = 0;
  local_2e4 = 0;
  local_2e8 = 0;
  local_2b2 = 1;
  local_2b4 = 0xe;
  local_2b8 = &DAT_80317fdc;
  local_2c8 = 4;
  local_2c4 = FLOAT_803e13dc;
  local_2c0 = FLOAT_803e13c8;
  local_2bc = FLOAT_803e13c8;
  local_29a = 1;
  local_29c = 0x15;
  local_2a0 = &DAT_80317fb0;
  local_2b0 = 0x4000;
  local_2ac = FLOAT_803e13d0;
  local_2a8 = FLOAT_803e13e0;
  local_2a4 = FLOAT_803e13c8;
  puVar2 = &local_298;
  if (param_2 != 1) {
    local_282[0] = 1;
    local_284 = 0;
    local_288 = 0;
    local_298 = 0x100;
    local_294 = FLOAT_803e13c8;
    local_290 = FLOAT_803e13c8;
    local_28c = FLOAT_803e13e4;
    puVar2 = (undefined4 *)(local_282 + 2);
  }
  *(undefined *)((int)puVar2 + 0x16) = 2;
  *(undefined2 *)(puVar2 + 5) = 0x15;
  puVar2[4] = &DAT_80317fb0;
  *puVar2 = 0x4000;
  puVar2[1] = FLOAT_803e13d0;
  puVar2[2] = FLOAT_803e13e0;
  puVar2[3] = FLOAT_803e13c8;
  *(undefined *)((int)puVar2 + 0x2e) = 3;
  *(undefined2 *)(puVar2 + 0xb) = 0x15;
  puVar2[10] = &DAT_80317fb0;
  puVar2[6] = 0x4000;
  puVar2[7] = FLOAT_803e13d0;
  puVar2[8] = FLOAT_803e13e0;
  puVar2[9] = FLOAT_803e13c8;
  *(undefined *)((int)puVar2 + 0x46) = 3;
  *(undefined2 *)(puVar2 + 0x11) = 0xe;
  puVar2[0x10] = &DAT_80317fdc;
  puVar2[0xc] = 4;
  puVar2[0xd] = FLOAT_803e13c8;
  puVar2[0xe] = FLOAT_803e13c8;
  puVar2[0xf] = FLOAT_803e13c8;
  *(undefined *)((int)puVar2 + 0x5e) = 1;
  local_330 = 0;
  local_344 = (undefined2)param_2;
  local_35c = FLOAT_803e13c8;
  local_358 = FLOAT_803e13c8;
  local_354 = FLOAT_803e13c8;
  local_368 = FLOAT_803e13c8;
  local_364 = FLOAT_803e13c8;
  local_360 = FLOAT_803e13c8;
  local_350 = FLOAT_803e13e8;
  local_348 = 2;
  local_34c = 7;
  local_32f = 0xe;
  local_32e = 0;
  local_32d = 0x1e;
  iVar1 = (int)puVar2 + (0x48 - (int)&local_328);
  iVar1 = iVar1 / 0x18 + (iVar1 >> 0x1f);
  local_32b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  iVar1 = param_2 * 7;
  local_342 = *(undefined2 *)(&DAT_80317ff8 + param_2 * 0xe);
  local_340 = *(undefined2 *)(&DAT_80317ff8 + (iVar1 + 1) * 2);
  local_33e = *(undefined2 *)(&DAT_80317ff8 + (iVar1 + 2) * 2);
  local_33c = *(undefined2 *)(&DAT_80317ff8 + (iVar1 + 3) * 2);
  local_33a = *(undefined2 *)(&DAT_80317ff8 + (iVar1 + 4) * 2);
  local_338 = *(undefined2 *)(&DAT_80317ff8 + (iVar1 + 5) * 2);
  local_336 = *(undefined2 *)(&DAT_80317ff8 + (iVar1 + 6) * 2);
  local_388 = &local_328;
  local_334 = param_4 | 0xc010480;
  if ((param_4 & 1) != 0) {
    if (param_1 == 0) {
      local_35c = FLOAT_803e13c8 + *(float *)(param_3 + 6);
      local_358 = FLOAT_803e13c8 + *(float *)(param_3 + 8);
      local_354 = FLOAT_803e13c8 + *(float *)(param_3 + 10);
    }
    else {
      local_35c = FLOAT_803e13c8 + *(float *)(param_1 + 0x18);
      local_358 = FLOAT_803e13c8 + *(float *)(param_1 + 0x1c);
      local_354 = FLOAT_803e13c8 + *(float *)(param_1 + 0x20);
    }
  }
  local_384 = param_1;
  local_2d4 = local_2dc;
  (**(code **)(*DAT_803dca7c + 8))(&local_388,0,0x15,&DAT_80317e00,0x18,&DAT_80317ed4,0x154,0);
  return;
}

