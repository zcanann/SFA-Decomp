// Function: FUN_800ff2a0
// Entry: 800ff2a0
// Size: 1684 bytes

/* WARNING: Removing unreachable block (ram,0x800ff914) */
/* WARNING: Removing unreachable block (ram,0x800ff2b0) */

void FUN_800ff2a0(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  undefined4 *puVar4;
  double in_f31;
  double dVar5;
  double in_ps31_1;
  undefined8 uVar6;
  undefined4 *local_3a8;
  int local_3a4;
  float local_388;
  float local_384;
  float local_380;
  float local_37c;
  float local_378;
  float local_374;
  float local_370;
  undefined4 local_36c;
  undefined4 local_368;
  undefined2 local_364;
  undefined2 local_362;
  undefined2 local_360;
  undefined2 local_35e;
  undefined2 local_35c;
  undefined2 local_35a;
  undefined2 local_358;
  undefined2 local_356;
  uint local_354;
  undefined local_350;
  undefined local_34f;
  undefined local_34e;
  undefined local_34d;
  char local_34b;
  undefined4 local_348;
  float local_344;
  float local_340;
  float local_33c;
  undefined *local_338;
  undefined2 local_334;
  undefined local_332 [2];
  undefined4 local_330 [5];
  undefined local_31a [722];
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar6 = FUN_8028683c();
  iVar2 = (int)((ulonglong)uVar6 >> 0x20);
  if ((int)uVar6 == 0) {
    local_332[0] = 0;
    local_334 = 3;
    local_338 = &DAT_803dc5e8;
    local_348 = 8;
    uVar3 = FUN_80022264(0,0x1e);
    uStack_44 = uVar3 + 0xe1 ^ 0x80000000;
    local_48 = 0x43300000;
    local_344 = (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e21e8);
    uVar3 = FUN_80022264(0,0x14);
    uStack_3c = uVar3 + 0x87 ^ 0x80000000;
    local_40 = 0x43300000;
    local_340 = (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e21e8);
    uVar3 = FUN_80022264(0,0x14);
    uStack_34 = uVar3 + 0x41 ^ 0x80000000;
    local_38 = 0x43300000;
    local_33c = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e21e8);
    puVar4 = (undefined4 *)(local_332 + 2);
  }
  else {
    puVar4 = &local_348;
    if ((int)uVar6 == 1) {
      local_332[0] = 0;
      local_334 = 3;
      local_338 = &DAT_803dc5e8;
      local_348 = 8;
      uVar3 = FUN_80022264(0,0x5a);
      uStack_34 = uVar3 + 0x87 ^ 0x80000000;
      local_38 = 0x43300000;
      local_344 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e21e8);
      local_340 = local_344;
      uVar3 = FUN_80022264(0,0x1e);
      uStack_3c = uVar3 + 0xe1 ^ 0x80000000;
      local_40 = 0x43300000;
      local_33c = (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e21e8);
      puVar4 = (undefined4 *)(local_332 + 2);
    }
  }
  uStack_34 = FUN_80022264(0,0xfffe);
  uStack_34 = uStack_34 ^ 0x80000000;
  local_38 = 0x43300000;
  dVar5 = (double)(float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e21e8);
  uStack_3c = FUN_80022264(0xfffff448,0xffffd120);
  uStack_3c = uStack_3c ^ 0x80000000;
  local_40 = 0x43300000;
  *(undefined *)((int)puVar4 + 0x16) = 0;
  *(undefined2 *)(puVar4 + 5) = 0;
  puVar4[4] = 0;
  *puVar4 = 0x80;
  puVar4[1] = FLOAT_803e21b0;
  puVar4[2] = (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e21e8);
  puVar4[3] = (float)dVar5;
  *(undefined *)((int)puVar4 + 0x2e) = 0;
  *(undefined2 *)(puVar4 + 0xb) = 3;
  puVar4[10] = &DAT_803dc5e8;
  puVar4[6] = 4;
  puVar4[7] = FLOAT_803e21b0;
  puVar4[8] = FLOAT_803e21b0;
  puVar4[9] = FLOAT_803e21b0;
  *(undefined *)((int)puVar4 + 0x46) = 0;
  *(undefined2 *)(puVar4 + 0x11) = 3;
  puVar4[0x10] = &DAT_803dc5e8;
  puVar4[0xc] = 2;
  puVar4[0xd] = FLOAT_803e21b4;
  uStack_44 = FUN_80022264(0,0x19);
  uStack_44 = uStack_44 ^ 0x80000000;
  local_48 = 0x43300000;
  puVar4[0xe] = FLOAT_803e21bc * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e21e8) +
                FLOAT_803e21b8;
  uStack_2c = FUN_80022264(0,10);
  uStack_2c = uStack_2c ^ 0x80000000;
  local_30 = 0x43300000;
  puVar4[0xf] = FLOAT_803e21bc * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e21e8) +
                FLOAT_803e21c0;
  *(undefined *)((int)puVar4 + 0x5e) = 1;
  *(undefined2 *)(puVar4 + 0x17) = 3;
  puVar4[0x16] = &DAT_803dc5e8;
  puVar4[0x12] = 4;
  uVar3 = FUN_80022264(0,10);
  if (uVar3 == 0) {
    uStack_2c = FUN_80022264(0,0x1e);
    uStack_2c = uStack_2c ^ 0x80000000;
    puVar4[0x13] = FLOAT_803e21c4 +
                   (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e21e8);
  }
  else {
    uStack_2c = FUN_80022264(0,10);
    uStack_2c = uStack_2c ^ 0x80000000;
    puVar4[0x13] = FLOAT_803e21c8 +
                   (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e21e8);
  }
  local_30 = 0x43300000;
  puVar4[0x14] = FLOAT_803e21b0;
  puVar4[0x15] = FLOAT_803e21b0;
  *(undefined *)((int)puVar4 + 0x76) = 1;
  *(undefined2 *)(puVar4 + 0x1d) = 0;
  puVar4[0x1c] = 0;
  puVar4[0x18] = 0x80;
  puVar4[0x19] = FLOAT_803e21b0;
  puVar4[0x1a] = FLOAT_803e21b0;
  uStack_2c = FUN_80022264(0,0xfffe);
  uStack_2c = uStack_2c ^ 0x80000000;
  local_30 = 0x43300000;
  puVar4[0x1b] = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e21e8);
  *(undefined *)((int)puVar4 + 0x8e) = 1;
  *(undefined2 *)(puVar4 + 0x23) = 3;
  puVar4[0x22] = &DAT_803dc5e8;
  puVar4[0x1e] = 2;
  puVar4[0x1f] = FLOAT_803e21cc;
  puVar4[0x20] = FLOAT_803e21d0;
  puVar4[0x21] = FLOAT_803e21d4;
  *(undefined *)((int)puVar4 + 0xa6) = 2;
  *(undefined2 *)(puVar4 + 0x29) = 0;
  puVar4[0x28] = 0;
  puVar4[0x24] = 0x80;
  puVar4[0x25] = FLOAT_803e21b0;
  puVar4[0x26] = FLOAT_803e21b0;
  uStack_34 = FUN_80022264(0,0xfffe);
  uStack_34 = uStack_34 ^ 0x80000000;
  local_38 = 0x43300000;
  puVar4[0x27] = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e21e8);
  *(undefined *)((int)puVar4 + 0xbe) = 2;
  *(undefined2 *)(puVar4 + 0x2f) = 3;
  puVar4[0x2e] = &DAT_803dc5e8;
  puVar4[0x2a] = 4;
  puVar4[0x2b] = FLOAT_803e21b0;
  puVar4[0x2c] = FLOAT_803e21b0;
  puVar4[0x2d] = FLOAT_803e21b0;
  *(undefined *)((int)puVar4 + 0xd6) = 2;
  *(undefined2 *)(puVar4 + 0x35) = 3;
  puVar4[0x34] = &DAT_803dc5e8;
  puVar4[0x30] = 2;
  puVar4[0x31] = FLOAT_803e21d8;
  puVar4[0x32] = FLOAT_803e21dc;
  puVar4[0x33] = FLOAT_803e21e0;
  local_350 = 0;
  local_364 = (undefined2)uVar6;
  local_37c = FLOAT_803e21b0;
  local_378 = FLOAT_803e21b0;
  local_374 = FLOAT_803e21b0;
  local_388 = FLOAT_803e21b0;
  local_384 = FLOAT_803e21b0;
  local_380 = FLOAT_803e21b0;
  local_370 = FLOAT_803e21e4;
  local_368 = 1;
  local_36c = 0;
  local_34f = 3;
  local_34e = 0;
  local_34d = 0;
  iVar1 = (int)puVar4 + (0xd8 - (int)&local_348);
  iVar1 = iVar1 / 0x18 + (iVar1 >> 0x1f);
  local_34b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_362 = DAT_80319a60;
  local_360 = DAT_80319a62;
  local_35e = DAT_80319a64;
  local_35c = DAT_80319a66;
  local_35a = DAT_80319a68;
  local_358 = DAT_80319a6a;
  local_356 = DAT_80319a6c;
  local_3a8 = &local_348;
  local_354 = param_4 | 0x4000400;
  if ((param_4 & 1) != 0) {
    if ((iVar2 == 0) || (param_3 == 0)) {
      if (iVar2 == 0) {
        if (param_3 != 0) {
          local_37c = FLOAT_803e21b0 + *(float *)(param_3 + 0xc);
          local_378 = FLOAT_803e21b0 + *(float *)(param_3 + 0x10);
          local_374 = FLOAT_803e21b0 + *(float *)(param_3 + 0x14);
        }
      }
      else {
        local_37c = FLOAT_803e21b0 + *(float *)(iVar2 + 0x18);
        local_378 = FLOAT_803e21b0 + *(float *)(iVar2 + 0x1c);
        local_374 = FLOAT_803e21b0 + *(float *)(iVar2 + 0x20);
      }
    }
    else {
      local_37c = FLOAT_803e21b0 + *(float *)(iVar2 + 0x18) + *(float *)(param_3 + 0xc);
      local_378 = FLOAT_803e21b0 + *(float *)(iVar2 + 0x1c) + *(float *)(param_3 + 0x10);
      local_374 = FLOAT_803e21b0 + *(float *)(iVar2 + 0x20) + *(float *)(param_3 + 0x14);
    }
  }
  local_3a4 = iVar2;
  (**(code **)(*DAT_803dd6fc + 8))(&local_3a8,0,3,&DAT_80319a40,1,&DAT_803dc5e0,0x26a,0);
  FUN_80286888();
  return;
}

