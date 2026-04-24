// Function: FUN_800ff93c
// Entry: 800ff93c
// Size: 1180 bytes

void FUN_800ff93c(short *param_1,int param_2,int param_3,uint param_4,undefined4 param_5,
                 uint *param_6)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *local_388;
  short *local_384;
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
  undefined4 local_2b8;
  undefined2 local_2b4;
  undefined local_2b2;
  undefined4 local_2b0;
  float local_2ac;
  float local_2a8;
  float local_2a4;
  undefined4 local_2a0;
  undefined2 local_29c;
  undefined local_29a [2];
  undefined4 local_298 [5];
  undefined local_282 [602];
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  
  uStack_1c = 0x30;
  uStack_24 = 0x31;
  uStack_14 = 1;
  local_2b4 = 0x50;
  if (param_6 != (uint *)0x0) {
    uStack_14 = *param_6;
    uStack_1c = param_6[1];
    uStack_24 = param_6[2];
    local_2b4 = (undefined2)param_6[3];
  }
  local_312 = 0;
  local_314 = 8;
  local_318 = &DAT_80319af8;
  local_328 = 4;
  local_324 = FLOAT_803e21f0;
  local_320 = FLOAT_803e21f0;
  local_31c = FLOAT_803e21f0;
  local_2fa = 0;
  local_2fc = 8;
  local_300 = &DAT_80319af8;
  local_310 = 2;
  if (param_1 == (short *)0x0) {
    local_308 = FLOAT_803e21f8;
    local_304 = FLOAT_803e21f4;
  }
  else {
    local_304 = FLOAT_803e21f4 * *(float *)(param_1 + 4);
    local_308 = FLOAT_803e21f8 * *(float *)(param_1 + 4);
  }
  local_2e2 = 0;
  local_2e4 = 0;
  local_2e8 = 0;
  local_2f8 = 0x80;
  local_2f4 = FLOAT_803e21f0;
  local_2f0 = FLOAT_803e21f0;
  if (param_1 == (short *)0x0) {
    local_2ec = FLOAT_803e21f0;
  }
  else {
    local_2ec = (float)((double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000) - DOUBLE_803e2210);
  }
  local_2ca = 1;
  local_2cc = 8;
  local_2d0 = &DAT_80319af8;
  local_2e0 = 4;
  local_2dc = FLOAT_803e21fc;
  local_2d8 = FLOAT_803e21f0;
  local_2d4 = FLOAT_803e21f0;
  local_2b2 = 1;
  local_2b8 = 0;
  local_2c8 = 0x20000000;
  local_2c4 = (float)((double)CONCAT44(0x43300000,uStack_14 ^ 0x80000000) - DOUBLE_803e2210);
  local_2c0 = (float)((double)CONCAT44(0x43300000,uStack_1c ^ 0x80000000) - DOUBLE_803e2210);
  local_2bc = (float)((double)CONCAT44(0x43300000,uStack_24 ^ 0x80000000) - DOUBLE_803e2210);
  puVar2 = &local_2b0;
  if (param_2 != 1) {
    local_29a[0] = 2;
    local_29c = 0x3b;
    local_2a0 = 0;
    local_2b0 = 0x1800000;
    local_2ac = FLOAT_803e2200;
    local_2a8 = FLOAT_803e21f0;
    local_2a4 = FLOAT_803e2204;
    puVar2 = (undefined4 *)(local_29a + 2);
  }
  *(undefined *)((int)puVar2 + 0x16) = 2;
  *(undefined2 *)(puVar2 + 5) = 0;
  puVar2[4] = 0;
  *puVar2 = 0x100;
  puVar2[1] = FLOAT_803e21f0;
  puVar2[2] = FLOAT_803e21f0;
  puVar2[3] = FLOAT_803e2208;
  *(undefined *)((int)puVar2 + 0x2e) = 3;
  *(undefined2 *)(puVar2 + 0xb) = 1;
  puVar2[10] = 0;
  puVar2[6] = 0x2000;
  puVar2[7] = FLOAT_803e21f0;
  puVar2[8] = FLOAT_803e21f0;
  puVar2[9] = FLOAT_803e21f0;
  *(undefined *)((int)puVar2 + 0x46) = 4;
  *(undefined2 *)(puVar2 + 0x11) = 8;
  puVar2[0x10] = &DAT_80319af8;
  puVar2[0xc] = 4;
  puVar2[0xd] = FLOAT_803e21f0;
  puVar2[0xe] = FLOAT_803e21f0;
  puVar2[0xf] = FLOAT_803e21f0;
  *(undefined *)((int)puVar2 + 0x5e) = 4;
  *(undefined2 *)(puVar2 + 0x17) = 0;
  puVar2[0x16] = 0;
  puVar2[0x12] = 0x20000000;
  uStack_14 = uStack_14 ^ 0x80000000;
  local_18 = 0x43300000;
  puVar2[0x13] = (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e2210);
  uStack_1c = uStack_1c ^ 0x80000000;
  local_20 = 0x43300000;
  puVar2[0x14] = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e2210);
  uStack_24 = uStack_24 ^ 0x80000000;
  local_28 = 0x43300000;
  puVar2[0x15] = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e2210);
  local_330 = (undefined)param_2;
  local_344 = (undefined2)param_2;
  local_35c = FLOAT_803e21f0;
  if (param_3 == 0) {
    local_358 = FLOAT_803e21f0;
  }
  else {
    local_358 = *(float *)(param_3 + 0x10);
  }
  local_354 = FLOAT_803e21f0;
  local_368 = FLOAT_803e21f0;
  local_364 = FLOAT_803e21f0;
  local_360 = FLOAT_803e21f0;
  local_350 = FLOAT_803e2200;
  local_348 = 1;
  local_34c = 0;
  local_32f = 8;
  local_32e = 0;
  local_32d = 0x1e;
  iVar1 = (int)puVar2 + (0x60 - (int)&local_328);
  iVar1 = iVar1 / 0x18 + (iVar1 >> 0x1f);
  local_32b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_342 = DAT_80319b08;
  local_340 = DAT_80319b0a;
  local_33e = DAT_80319b0c;
  local_33c = DAT_80319b0e;
  local_33a = DAT_80319b10;
  local_338 = DAT_80319b12;
  local_336 = DAT_80319b14;
  local_388 = &local_328;
  local_334 = param_4 | 0x4040080;
  if ((param_4 & 1) != 0) {
    if (param_1 == (short *)0x0) {
      local_35c = FLOAT_803e21f0 + *(float *)(param_3 + 0xc);
      local_358 = local_358 + *(float *)(param_3 + 0x10);
      local_354 = FLOAT_803e21f0 + *(float *)(param_3 + 0x14);
    }
    else {
      local_35c = FLOAT_803e21f0 + *(float *)(param_1 + 0xc);
      local_358 = local_358 + *(float *)(param_1 + 0xe);
      local_354 = FLOAT_803e21f0 + *(float *)(param_1 + 0x10);
    }
  }
  local_384 = param_1;
  local_30c = local_304;
  (**(code **)(*DAT_803dd6fc + 8))(&local_388,0,8,&DAT_80319a90,4,&DAT_80319ae0,0x5e0,0);
  return;
}

