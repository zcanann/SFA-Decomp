// Function: FUN_800f5d28
// Entry: 800f5d28
// Size: 1724 bytes

void FUN_800f5d28(int param_1,int param_2,int param_3,uint param_4)

{
  float fVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
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
  undefined local_2c2;
  undefined4 local_2c0;
  float local_2bc;
  float local_2b8;
  float local_2b4;
  undefined4 local_2b0;
  undefined2 local_2ac;
  undefined local_2aa;
  undefined4 local_2a8;
  float local_2a4;
  float local_2a0;
  float local_29c;
  undefined *local_298;
  undefined2 local_294;
  undefined local_292;
  undefined4 local_290;
  float local_28c;
  float local_288;
  float local_284;
  undefined *local_280;
  undefined2 local_27c;
  undefined local_27a [2];
  undefined4 local_278 [5];
  undefined local_262 [606];
  
  fVar1 = FLOAT_803e1af8;
  if (((param_2 == 0) || (param_2 == 2)) || (param_2 == 0x1e)) {
    DAT_80316392 = 0xc;
  }
  else if ((param_2 == 1) || (param_2 == 3)) {
    fVar1 = FLOAT_803e1af8 * FLOAT_803e1afc;
    DAT_80316392 = 4;
    DAT_80316398 = 0x32;
  }
  local_2f2 = 0;
  local_2f4 = 0x15;
  local_2f8 = &DAT_80316348;
  local_308 = 4;
  local_304 = FLOAT_803e1b00;
  local_300 = FLOAT_803e1b00;
  local_2fc = FLOAT_803e1b00;
  if ((param_2 == 0) || (param_2 == 2)) {
    local_2e8 = FLOAT_803e1b04;
    local_2e4 = FLOAT_803e1b08;
  }
  else if (param_2 == 0xe) {
    local_2e8 = FLOAT_803e1b0c;
    local_2e4 = FLOAT_803e1b10;
  }
  else if (param_2 == 0x1e) {
    local_2e8 = FLOAT_803e1b14;
    local_2e4 = FLOAT_803e1b08;
  }
  else {
    local_2e8 = FLOAT_803e1b04;
    local_2e4 = FLOAT_803e1b18;
  }
  local_2da = 0;
  local_2dc = 0x15;
  local_2e0 = &DAT_80316348;
  local_2f0 = 2;
  local_2c2 = 0;
  local_2c4 = 0x77;
  local_2c8 = 0;
  local_2d8 = 0x10000;
  local_2d4 = FLOAT_803e1b00;
  local_2d0 = FLOAT_803e1b00;
  local_2cc = FLOAT_803e1b00;
  local_2aa = 0;
  local_2ac = 0x79;
  local_2b0 = 0;
  local_2c0 = 0x10000;
  local_2bc = FLOAT_803e1b00;
  local_2b8 = FLOAT_803e1b00;
  local_2b4 = FLOAT_803e1b00;
  local_292 = 1;
  local_294 = 0x15;
  local_298 = &DAT_80316348;
  local_2a8 = 4;
  local_2a4 = FLOAT_803e1b1c;
  local_2a0 = FLOAT_803e1b00;
  local_29c = FLOAT_803e1b00;
  puVar4 = &local_290;
  if ((param_2 == 0) || (param_2 == 2)) {
    local_27a[0] = 1;
    local_27c = 0x15;
    local_280 = &DAT_80316348;
    local_290 = 2;
    local_28c = FLOAT_803e1b20;
    local_288 = FLOAT_803e1b20;
    local_284 = FLOAT_803e1b24;
    puVar4 = (undefined4 *)(local_27a + 2);
  }
  else if (param_2 == 0x1e) {
    local_27a[0] = 1;
    local_27c = 0x15;
    local_280 = &DAT_80316348;
    local_290 = 2;
    local_28c = FLOAT_803e1b20;
    local_288 = FLOAT_803e1b20;
    local_284 = FLOAT_803e1b28;
    puVar4 = (undefined4 *)(local_27a + 2);
  }
  *(undefined *)((int)puVar4 + 0x16) = 1;
  *(undefined2 *)(puVar4 + 5) = 0x15;
  puVar4[4] = &DAT_80316348;
  *puVar4 = 0x4000;
  puVar4[1] = FLOAT_803e1b20;
  puVar4[2] = fVar1;
  puVar4[3] = FLOAT_803e1b00;
  *(undefined *)((int)puVar4 + 0x2e) = 2;
  *(undefined2 *)(puVar4 + 0xb) = 0x15;
  puVar4[10] = &DAT_80316348;
  puVar4[6] = 4;
  puVar4[7] = FLOAT_803e1b1c;
  puVar4[8] = FLOAT_803e1b00;
  puVar4[9] = FLOAT_803e1b00;
  *(undefined *)((int)puVar4 + 0x46) = 2;
  *(undefined2 *)(puVar4 + 0x11) = 0x15;
  puVar4[0x10] = &DAT_80316348;
  puVar4[0xc] = 0x4000;
  puVar4[0xd] = FLOAT_803e1b20;
  puVar4[0xe] = fVar1;
  puVar4[0xf] = FLOAT_803e1b00;
  *(undefined *)((int)puVar4 + 0x5e) = 3;
  *(undefined2 *)(puVar4 + 0x17) = 0x15;
  puVar4[0x16] = &DAT_80316348;
  puVar4[0x12] = 0x4000;
  puVar4[0x13] = FLOAT_803e1b20;
  puVar4[0x14] = fVar1;
  puVar4[0x15] = FLOAT_803e1b00;
  *(undefined *)((int)puVar4 + 0x76) = 4;
  *(undefined2 *)(puVar4 + 0x1d) = 0x15;
  puVar4[0x1c] = &DAT_80316348;
  puVar4[0x18] = 0x4000;
  puVar4[0x19] = FLOAT_803e1b20;
  puVar4[0x1a] = fVar1;
  puVar4[0x1b] = FLOAT_803e1b00;
  puVar3 = puVar4 + 0x1e;
  if ((param_2 == 0) || (param_2 == 0x1e)) {
    *(undefined *)((int)puVar4 + 0x8e) = 4;
    *(undefined2 *)(puVar4 + 0x23) = 2;
    puVar4[0x22] = 0;
    *puVar3 = 0x2000;
    puVar4[0x1f] = FLOAT_803e1b00;
    puVar4[0x20] = FLOAT_803e1b00;
    puVar4[0x21] = FLOAT_803e1b00;
    puVar3 = puVar4 + 0x24;
  }
  *(undefined *)((int)puVar3 + 0x16) = 5;
  *(undefined2 *)(puVar3 + 5) = 0x15;
  puVar3[4] = &DAT_80316348;
  *puVar3 = 0x4000;
  puVar3[1] = FLOAT_803e1b20;
  puVar3[2] = fVar1;
  puVar3[3] = FLOAT_803e1b00;
  *(undefined *)((int)puVar3 + 0x2e) = 5;
  *(undefined2 *)(puVar3 + 0xb) = 0x15;
  puVar3[10] = &DAT_80316348;
  puVar3[6] = 4;
  puVar3[7] = FLOAT_803e1b00;
  puVar3[8] = FLOAT_803e1b00;
  puVar3[9] = FLOAT_803e1b00;
  puVar4 = puVar3 + 0xc;
  if ((param_2 == 1) || (param_2 == 3)) {
    *(undefined *)((int)puVar3 + 0x46) = 5;
    *(undefined2 *)(puVar3 + 0x11) = 0x15;
    puVar3[0x10] = &DAT_80316348;
    *puVar4 = 2;
    puVar3[0xd] = FLOAT_803e1b20;
    puVar3[0xe] = FLOAT_803e1b20;
    puVar3[0xf] = FLOAT_803e1b08;
    puVar4 = puVar3 + 0x12;
  }
  *(undefined *)((int)puVar4 + 0x16) = 5;
  *(undefined2 *)(puVar4 + 5) = 0x78;
  puVar4[4] = 0;
  *puVar4 = 0x10000;
  puVar4[1] = FLOAT_803e1b00;
  puVar4[2] = FLOAT_803e1b00;
  puVar4[3] = FLOAT_803e1b00;
  *(undefined *)((int)puVar4 + 0x2e) = 5;
  *(undefined2 *)(puVar4 + 0xb) = 0xffff;
  puVar4[10] = 0;
  puVar4[6] = 0x10000;
  puVar4[7] = FLOAT_803e1b00;
  puVar4[8] = FLOAT_803e1b00;
  puVar4[9] = FLOAT_803e1b00;
  local_310 = 0;
  local_324 = (undefined2)param_2;
  local_33c = FLOAT_803e1b00;
  local_338 = FLOAT_803e1b00;
  local_334 = FLOAT_803e1b00;
  local_348 = FLOAT_803e1b00;
  local_344 = FLOAT_803e1b00;
  local_340 = FLOAT_803e1b00;
  local_330 = FLOAT_803e1b20;
  local_328 = 2;
  local_32c = 7;
  local_30f = 0xe;
  local_30e = 0;
  local_30d = 10;
  iVar2 = (int)puVar4 + (0x30 - (int)&local_308);
  iVar2 = iVar2 / 0x18 + (iVar2 >> 0x1f);
  local_30b = (char)iVar2 - (char)(iVar2 >> 0x1f);
  local_322 = DAT_80316390;
  local_320 = DAT_80316392;
  local_31e = DAT_80316394;
  local_31c = DAT_80316396;
  local_31a = DAT_80316398;
  local_318 = DAT_8031639a;
  local_316 = DAT_8031639c;
  local_368 = &local_308;
  local_314 = param_4 | 0xc0104c0;
  if ((param_4 & 1) != 0) {
    if (param_1 == 0) {
      local_33c = FLOAT_803e1b00 + *(float *)(param_3 + 0xc);
      local_338 = FLOAT_803e1b00 + *(float *)(param_3 + 0x10);
      local_334 = FLOAT_803e1b00 + *(float *)(param_3 + 0x14);
    }
    else {
      local_33c = FLOAT_803e1b00 + *(float *)(param_1 + 0x18);
      local_338 = FLOAT_803e1b00 + *(float *)(param_1 + 0x1c);
      local_334 = FLOAT_803e1b00 + *(float *)(param_1 + 0x20);
    }
  }
  local_364 = param_1;
  local_2ec = local_2e8;
  if (param_2 == 0x1e) {
    (**(code **)(*DAT_803dd6fc + 8))(&local_368,0,0x15,&DAT_80316198,0x18,&DAT_8031626c,0x3e9,0);
  }
  else if ((param_2 == 2) || (param_2 == 3)) {
    (**(code **)(*DAT_803dd6fc + 8))(&local_368,0,0x15,&DAT_80316198,0x18,&DAT_8031626c,0x23d,0);
  }
  else if ((param_2 - 10U < 4) || (param_2 == 0xe)) {
    (**(code **)(*DAT_803dd6fc + 8))(&local_368,0,0x15,&DAT_80316198,0x18,&DAT_8031626c,0x2e,0);
  }
  else {
    (**(code **)(*DAT_803dd6fc + 8))(&local_368,0,0x15,&DAT_80316198,0x18,&DAT_8031626c,0xd9,0);
  }
  return;
}

