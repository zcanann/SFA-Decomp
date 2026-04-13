// Function: FUN_800f557c
// Entry: 800f557c
// Size: 1264 bytes

void FUN_800f557c(int param_1,int param_2,int param_3,uint param_4)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
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
  undefined *local_2e0;
  undefined2 local_2dc;
  undefined local_2da [2];
  undefined4 local_2d8 [5];
  undefined local_2c2 [706];
  
  local_2f2 = 0;
  local_2f4 = 0x8c;
  local_2f8 = 0;
  local_308 = 0x20000000;
  local_304 = FLOAT_803e1aa0;
  local_300 = FLOAT_803e1aa4;
  local_2fc = FLOAT_803e1aa8;
  puVar2 = &local_2f0;
  if (param_2 != 2) {
    local_2da[0] = 0;
    local_2dc = 9;
    local_2e0 = &DAT_80316060;
    local_2f0 = 0x80;
    local_2ec = FLOAT_803e1aac;
    local_2e8 = FLOAT_803e1aac;
    local_2e4 = FLOAT_803e1ab0;
    puVar2 = (undefined4 *)(local_2da + 2);
  }
  if (param_2 == 0) {
    *(undefined *)((int)puVar2 + 0x16) = 0;
    *(undefined2 *)(puVar2 + 5) = 8;
    puVar2[4] = &DAT_80316074;
    *puVar2 = 2;
    puVar2[1] = FLOAT_803e1ab4;
    puVar2[2] = FLOAT_803e1ab4;
    puVar2[3] = FLOAT_803e1ab8;
  }
  else {
    *(undefined *)((int)puVar2 + 0x16) = 0;
    *(undefined2 *)(puVar2 + 5) = 8;
    puVar2[4] = &DAT_80316074;
    *puVar2 = 2;
    puVar2[1] = FLOAT_803e1abc;
    puVar2[2] = FLOAT_803e1abc;
    puVar2[3] = FLOAT_803e1ac0;
  }
  if (param_2 == 0) {
    *(undefined *)((int)puVar2 + 0x2e) = 1;
    *(undefined2 *)(puVar2 + 0xb) = 8;
    puVar2[10] = &DAT_80316060;
    puVar2[6] = 2;
    puVar2[7] = FLOAT_803e1ac4;
    puVar2[8] = FLOAT_803e1ac4;
    puVar2[9] = FLOAT_803e1ac4;
  }
  else {
    *(undefined *)((int)puVar2 + 0x2e) = 1;
    *(undefined2 *)(puVar2 + 0xb) = 8;
    puVar2[10] = &DAT_80316060;
    puVar2[6] = 2;
    puVar2[7] = FLOAT_803e1ac4;
    puVar2[8] = FLOAT_803e1ac4;
    puVar2[9] = FLOAT_803e1ac4;
  }
  puVar3 = puVar2 + 0xc;
  if (param_2 == 0) {
    *(undefined *)((int)puVar2 + 0x46) = 1;
    *(undefined2 *)(puVar2 + 0x11) = 9;
    puVar2[0x10] = &DAT_80316060;
    *puVar3 = 0x100;
    puVar2[0xd] = FLOAT_803e1ac8;
    puVar2[0xe] = FLOAT_803e1aac;
    puVar2[0xf] = FLOAT_803e1aac;
    puVar3 = puVar2 + 0x12;
    *(undefined *)((int)puVar2 + 0x5e) = 1;
    *(undefined2 *)(puVar2 + 0x17) = 1;
    puVar2[0x16] = &DAT_803dc548;
    *puVar3 = 0x4000;
    puVar2[0x13] = FLOAT_803e1acc;
    puVar2[0x14] = FLOAT_803e1acc;
    puVar2[0x15] = FLOAT_803e1aac;
  }
  else if (param_2 == 1) {
    *(undefined *)((int)puVar2 + 0x46) = 1;
    *(undefined2 *)(puVar2 + 0x11) = 9;
    puVar2[0x10] = &DAT_80316060;
    *puVar3 = 0x100;
    puVar2[0xd] = FLOAT_803e1ad0;
    puVar2[0xe] = FLOAT_803e1aac;
    puVar2[0xf] = FLOAT_803e1aac;
    puVar3 = puVar2 + 0x12;
  }
  if (param_2 == 0) {
    *(undefined *)((int)puVar3 + 0x16) = 2;
    *(undefined2 *)(puVar3 + 5) = 9;
    puVar3[4] = &DAT_80316060;
    *puVar3 = 0x100;
    puVar3[1] = FLOAT_803e1ac8;
    puVar3[2] = FLOAT_803e1aac;
    puVar3[3] = FLOAT_803e1aac;
    *(undefined *)((int)puVar3 + 0x2e) = 2;
    *(undefined2 *)(puVar3 + 0xb) = 1;
    puVar3[10] = &DAT_803dc548;
    puVar3[6] = 0x4000;
    puVar3[7] = FLOAT_803e1acc;
    puVar3[8] = FLOAT_803e1acc;
    puVar3[9] = FLOAT_803e1aac;
    puVar3 = puVar3 + 6;
  }
  else if (param_2 == 1) {
    *(undefined *)((int)puVar3 + 0x16) = 2;
    *(undefined2 *)(puVar3 + 5) = 9;
    puVar3[4] = &DAT_80316060;
    *puVar3 = 0x100;
    puVar3[1] = FLOAT_803e1ad0;
    puVar3[2] = FLOAT_803e1aac;
    puVar3[3] = FLOAT_803e1aac;
    puVar3 = puVar3 + 6;
  }
  *(undefined *)((int)puVar3 + 0x16) = 2;
  *(undefined2 *)(puVar3 + 5) = 9;
  puVar3[4] = &DAT_80316060;
  *puVar3 = 4;
  puVar3[1] = FLOAT_803e1aac;
  puVar3[2] = FLOAT_803e1aac;
  puVar3[3] = FLOAT_803e1aac;
  *(undefined *)((int)puVar3 + 0x2e) = 3;
  *(undefined2 *)(puVar3 + 0xb) = 0;
  puVar3[10] = 0;
  puVar3[6] = 0x20000000;
  puVar3[7] = FLOAT_803e1aa0;
  puVar3[8] = FLOAT_803e1aa4;
  puVar3[9] = FLOAT_803e1aa8;
  local_324 = (undefined2)param_2;
  local_33c = FLOAT_803e1aac;
  local_338 = FLOAT_803e1aac;
  local_334 = FLOAT_803e1aac;
  local_348 = FLOAT_803e1aac;
  local_344 = FLOAT_803e1aac;
  local_340 = FLOAT_803e1aac;
  local_330 = FLOAT_803e1ad4;
  local_328 = 1;
  local_32c = 0;
  local_30f = 9;
  local_30e = 0;
  local_30d = 0x20;
  iVar1 = (int)puVar3 + (0x30 - (int)&local_308);
  iVar1 = iVar1 / 0x18 + (iVar1 >> 0x1f);
  local_30b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_322 = DAT_80316084;
  local_320 = DAT_80316086;
  local_31e = DAT_80316088;
  local_31c = DAT_8031608a;
  local_31a = DAT_8031608c;
  local_318 = DAT_8031608e;
  local_316 = DAT_80316090;
  local_368 = &local_308;
  local_314 = param_4 | 0x4000000;
  if ((param_4 & 1) != 0) {
    if (param_1 == 0) {
      local_33c = FLOAT_803e1aac + *(float *)(param_3 + 0xc);
      local_338 = FLOAT_803e1aac + *(float *)(param_3 + 0x10);
      local_334 = FLOAT_803e1aac + *(float *)(param_3 + 0x14);
    }
    else {
      local_33c = FLOAT_803e1aac + *(float *)(param_1 + 0x18);
      local_338 = FLOAT_803e1aac + *(float *)(param_1 + 0x1c);
      local_334 = FLOAT_803e1aac + *(float *)(param_1 + 0x20);
    }
  }
  local_364 = param_1;
  if (param_2 == 0) {
    local_310 = 0;
    (**(code **)(*DAT_803dd6fc + 8))(&local_368,0,9,&DAT_80315f78,8,&DAT_80316030,0x156,0);
  }
  else {
    local_310 = 0;
    (**(code **)(*DAT_803dd6fc + 8))(&local_368,0,9,&DAT_80315fd4,8,&DAT_80316030,0x8a,0);
  }
  return;
}

