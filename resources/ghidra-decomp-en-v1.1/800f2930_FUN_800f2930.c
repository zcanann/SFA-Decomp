// Function: FUN_800f2930
// Entry: 800f2930
// Size: 1008 bytes

void FUN_800f2930(int param_1,int param_2,int param_3,uint param_4)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *local_368;
  int local_364;
  float local_348;
  float local_344;
  float local_340;
  float local_33c;
  float local_338;
  float local_334;
  float local_330;
  undefined4 local_32c;
  undefined4 local_328;
  undefined2 local_324;
  undefined2 local_322;
  undefined2 local_320;
  undefined2 local_31e;
  undefined2 local_31c;
  undefined2 local_31a;
  undefined2 local_318;
  undefined2 local_316;
  uint local_314;
  undefined local_310;
  undefined local_30f;
  undefined local_30e;
  undefined local_30d;
  char local_30b;
  undefined4 local_308;
  float local_304;
  float local_300;
  float local_2fc;
  undefined4 local_2f8;
  undefined2 local_2f4;
  undefined local_2f2;
  undefined4 local_2f0;
  float local_2ec;
  float local_2e8;
  float local_2e4;
  undefined4 local_2e0;
  undefined2 local_2dc;
  undefined local_2da [2];
  undefined4 local_2d8;
  float local_2d4;
  float local_2d0;
  float local_2cc;
  undefined4 local_2c8;
  undefined2 local_2c4;
  undefined local_2c2;
  undefined4 local_2c0;
  float local_2bc;
  float local_2b8;
  float local_2b4;
  undefined4 local_2b0;
  undefined2 local_2ac;
  undefined local_2aa;
  undefined4 local_2a8 [170];
  
  local_2f4 = 100;
  local_300 = FLOAT_803e1868;
  local_2fc = FLOAT_803e186c;
  if (param_2 == 0) {
    local_2f4 = 0x8c;
  }
  else if (param_2 == 1) {
    local_2f4 = 0x8c;
    local_300 = FLOAT_803e1870;
    local_2fc = FLOAT_803e1874;
  }
  else if (param_2 == 2) {
    local_2f4 = 0x8c;
    local_300 = FLOAT_803e1878;
    local_2fc = FLOAT_803e187c;
  }
  else if (param_2 == 3) {
    local_2f4 = 0x8c;
    local_300 = FLOAT_803e1880;
    local_2fc = FLOAT_803e1884;
  }
  else if (param_2 == 4) {
    local_2f4 = 0x154;
    local_300 = FLOAT_803e1888;
    local_2fc = FLOAT_803e188c;
  }
  else if (param_2 == 5) {
    local_2f4 = 0x280;
    DAT_80315574 = 800;
    local_300 = FLOAT_803e1890;
    local_2fc = FLOAT_803e1894;
  }
  else if (param_2 == 6) {
    local_2f4 = 100;
    DAT_80315574 = 0x14;
    local_300 = FLOAT_803e1898;
    local_2fc = FLOAT_803e189c;
  }
  else if (param_2 == 7) {
    local_2f4 = 200;
    DAT_80315572 = 0x14;
    DAT_80315574 = 0x14;
    DAT_80315576 = 0x14;
    local_300 = FLOAT_803e18a0;
    local_2fc = FLOAT_803e18a4;
  }
  else if (param_2 == 8) {
    local_2f4 = 0x41;
    DAT_80315572 = 0x14;
    DAT_80315574 = 0x14;
    DAT_80315576 = 0x14;
    local_300 = FLOAT_803e18a8;
    local_2fc = FLOAT_803e18ac;
  }
  local_2f2 = 0;
  local_2f8 = 0;
  local_308 = 0x20000000;
  local_304 = FLOAT_803e18b0;
  puVar2 = &local_2f0;
  if (param_2 == 0) {
    local_2da[0] = 0;
    local_2dc = 0;
    local_2e0 = 0;
    local_2f0 = 0x80000;
    local_2ec = FLOAT_803e18b4;
    local_2e8 = FLOAT_803e18b8;
    local_2e4 = FLOAT_803e18b4;
    local_2c2 = 1;
    local_2c4 = 0;
    local_2c8 = 0;
    local_2d8 = 0x80000;
    local_2d4 = FLOAT_803e18b4;
    local_2d0 = FLOAT_803e18b4;
    local_2cc = FLOAT_803e18b4;
    local_2aa = 3;
    local_2ac = 0;
    local_2b0 = 0;
    local_2c0 = 0x80000;
    local_2bc = FLOAT_803e18b4;
    local_2b8 = FLOAT_803e18b8;
    local_2b4 = FLOAT_803e18b4;
    puVar2 = local_2a8;
  }
  else if (param_2 == 6) {
    local_2da[0] = 3;
    local_2dc = 1;
    local_2e0 = 0;
    local_2f0 = 0x2000;
    local_2ec = FLOAT_803e18b4;
    local_2e8 = FLOAT_803e18b4;
    local_2e4 = FLOAT_803e18b4;
    puVar2 = &local_2d8;
  }
  else if (param_2 == 8) {
    local_2da[0] = 3;
    local_2dc = 1;
    local_2e0 = 0;
    local_2f0 = 0x2000;
    local_2ec = FLOAT_803e18b4;
    local_2e8 = FLOAT_803e18b4;
    local_2e4 = FLOAT_803e18b4;
    puVar2 = &local_2d8;
  }
  *(undefined *)((int)puVar2 + 0x16) = 4;
  *(undefined2 *)(puVar2 + 5) = 0;
  puVar2[4] = 0;
  *puVar2 = 0x20000000;
  puVar2[1] = FLOAT_803e18b0;
  puVar2[2] = local_300;
  puVar2[3] = local_2fc;
  local_310 = 0;
  local_324 = (undefined2)param_2;
  local_33c = FLOAT_803e18b4;
  local_338 = FLOAT_803e18b4;
  local_334 = FLOAT_803e18b4;
  local_348 = FLOAT_803e18b4;
  local_344 = FLOAT_803e18b4;
  local_340 = FLOAT_803e18b4;
  local_330 = FLOAT_803e18bc;
  local_328 = 0;
  local_32c = 0;
  local_30f = 0;
  local_30e = 0;
  local_30d = 0;
  iVar1 = (int)puVar2 + (0x18 - (int)&local_308);
  iVar1 = iVar1 / 0x18 + (iVar1 >> 0x1f);
  local_30b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_322 = DAT_80315570;
  local_320 = DAT_80315572;
  local_31e = DAT_80315574;
  local_31c = DAT_80315576;
  local_31a = DAT_80315578;
  local_318 = DAT_8031557a;
  local_316 = DAT_8031557c;
  local_368 = &local_308;
  local_314 = param_4 | 0x10800;
  if ((param_4 & 1) != 0) {
    if (param_1 == 0) {
      local_33c = FLOAT_803e18b4 + *(float *)(param_3 + 0xc);
      local_338 = FLOAT_803e18b4 + *(float *)(param_3 + 0x10);
      local_334 = FLOAT_803e18b4 + *(float *)(param_3 + 0x14);
    }
    else {
      local_33c = FLOAT_803e18b4 + *(float *)(param_1 + 0x18);
      local_338 = FLOAT_803e18b4 + *(float *)(param_1 + 0x1c);
      local_334 = FLOAT_803e18b4 + *(float *)(param_1 + 0x20);
    }
  }
  local_364 = param_1;
  (**(code **)(*DAT_803dd6fc + 8))(&local_368,0,0,0,0,0,0,0);
  return;
}

