// Function: FUN_800ff004
// Entry: 800ff004
// Size: 1684 bytes

/* WARNING: Removing unreachable block (ram,0x800ff678) */

void FUN_800ff004(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 uVar3;
  undefined8 in_f31;
  double dVar4;
  undefined8 uVar5;
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
  uint uStack68;
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  undefined4 local_30;
  uint uStack44;
  undefined auStack8 [8];
  
  uVar3 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar5 = FUN_802860d8();
  local_3a4 = (int)((ulonglong)uVar5 >> 0x20);
  if ((int)uVar5 == 0) {
    local_332[0] = 0;
    local_334 = 3;
    local_338 = &DAT_803db988;
    local_348 = 8;
    iVar1 = FUN_800221a0(0,0x1e);
    uStack68 = iVar1 + 0xe1U ^ 0x80000000;
    local_48 = 0x43300000;
    local_344 = (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e1568);
    iVar1 = FUN_800221a0(0,0x14);
    uStack60 = iVar1 + 0x87U ^ 0x80000000;
    local_40 = 0x43300000;
    local_340 = (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e1568);
    iVar1 = FUN_800221a0(0,0x14);
    uStack52 = iVar1 + 0x41U ^ 0x80000000;
    local_38 = 0x43300000;
    local_33c = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e1568);
    puVar2 = (undefined4 *)(local_332 + 2);
  }
  else {
    puVar2 = &local_348;
    if ((int)uVar5 == 1) {
      local_332[0] = 0;
      local_334 = 3;
      local_338 = &DAT_803db988;
      local_348 = 8;
      iVar1 = FUN_800221a0(0,0x5a);
      uStack52 = iVar1 + 0x87U ^ 0x80000000;
      local_38 = 0x43300000;
      local_344 = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e1568);
      local_340 = local_344;
      iVar1 = FUN_800221a0(0,0x1e);
      uStack60 = iVar1 + 0xe1U ^ 0x80000000;
      local_40 = 0x43300000;
      local_33c = (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e1568);
      puVar2 = (undefined4 *)(local_332 + 2);
    }
  }
  uStack52 = FUN_800221a0(0,0xfffe);
  uStack52 = uStack52 ^ 0x80000000;
  local_38 = 0x43300000;
  dVar4 = (double)(float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e1568);
  uStack60 = FUN_800221a0(0xfffff448,0xffffd120);
  uStack60 = uStack60 ^ 0x80000000;
  local_40 = 0x43300000;
  *(undefined *)((int)puVar2 + 0x16) = 0;
  *(undefined2 *)(puVar2 + 5) = 0;
  puVar2[4] = 0;
  *puVar2 = 0x80;
  puVar2[1] = FLOAT_803e1530;
  puVar2[2] = (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e1568);
  puVar2[3] = (float)dVar4;
  *(undefined *)((int)puVar2 + 0x2e) = 0;
  *(undefined2 *)(puVar2 + 0xb) = 3;
  puVar2[10] = &DAT_803db988;
  puVar2[6] = 4;
  puVar2[7] = FLOAT_803e1530;
  puVar2[8] = FLOAT_803e1530;
  puVar2[9] = FLOAT_803e1530;
  *(undefined *)((int)puVar2 + 0x46) = 0;
  *(undefined2 *)(puVar2 + 0x11) = 3;
  puVar2[0x10] = &DAT_803db988;
  puVar2[0xc] = 2;
  puVar2[0xd] = FLOAT_803e1534;
  uStack68 = FUN_800221a0(0,0x19);
  uStack68 = uStack68 ^ 0x80000000;
  local_48 = 0x43300000;
  puVar2[0xe] = FLOAT_803e153c * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e1568) +
                FLOAT_803e1538;
  uStack44 = FUN_800221a0(0,10);
  uStack44 = uStack44 ^ 0x80000000;
  local_30 = 0x43300000;
  puVar2[0xf] = FLOAT_803e153c * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e1568) +
                FLOAT_803e1540;
  *(undefined *)((int)puVar2 + 0x5e) = 1;
  *(undefined2 *)(puVar2 + 0x17) = 3;
  puVar2[0x16] = &DAT_803db988;
  puVar2[0x12] = 4;
  iVar1 = FUN_800221a0(0,10);
  if (iVar1 == 0) {
    uStack44 = FUN_800221a0(0,0x1e);
    uStack44 = uStack44 ^ 0x80000000;
    puVar2[0x13] = FLOAT_803e1544 + (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e1568)
    ;
  }
  else {
    uStack44 = FUN_800221a0(0,10);
    uStack44 = uStack44 ^ 0x80000000;
    puVar2[0x13] = FLOAT_803e1548 + (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e1568)
    ;
  }
  local_30 = 0x43300000;
  puVar2[0x14] = FLOAT_803e1530;
  puVar2[0x15] = FLOAT_803e1530;
  *(undefined *)((int)puVar2 + 0x76) = 1;
  *(undefined2 *)(puVar2 + 0x1d) = 0;
  puVar2[0x1c] = 0;
  puVar2[0x18] = 0x80;
  puVar2[0x19] = FLOAT_803e1530;
  puVar2[0x1a] = FLOAT_803e1530;
  uStack44 = FUN_800221a0(0,0xfffe);
  uStack44 = uStack44 ^ 0x80000000;
  local_30 = 0x43300000;
  puVar2[0x1b] = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e1568);
  *(undefined *)((int)puVar2 + 0x8e) = 1;
  *(undefined2 *)(puVar2 + 0x23) = 3;
  puVar2[0x22] = &DAT_803db988;
  puVar2[0x1e] = 2;
  puVar2[0x1f] = FLOAT_803e154c;
  puVar2[0x20] = FLOAT_803e1550;
  puVar2[0x21] = FLOAT_803e1554;
  *(undefined *)((int)puVar2 + 0xa6) = 2;
  *(undefined2 *)(puVar2 + 0x29) = 0;
  puVar2[0x28] = 0;
  puVar2[0x24] = 0x80;
  puVar2[0x25] = FLOAT_803e1530;
  puVar2[0x26] = FLOAT_803e1530;
  uStack52 = FUN_800221a0(0,0xfffe);
  uStack52 = uStack52 ^ 0x80000000;
  local_38 = 0x43300000;
  puVar2[0x27] = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e1568);
  *(undefined *)((int)puVar2 + 0xbe) = 2;
  *(undefined2 *)(puVar2 + 0x2f) = 3;
  puVar2[0x2e] = &DAT_803db988;
  puVar2[0x2a] = 4;
  puVar2[0x2b] = FLOAT_803e1530;
  puVar2[0x2c] = FLOAT_803e1530;
  puVar2[0x2d] = FLOAT_803e1530;
  *(undefined *)((int)puVar2 + 0xd6) = 2;
  *(undefined2 *)(puVar2 + 0x35) = 3;
  puVar2[0x34] = &DAT_803db988;
  puVar2[0x30] = 2;
  puVar2[0x31] = FLOAT_803e1558;
  puVar2[0x32] = FLOAT_803e155c;
  puVar2[0x33] = FLOAT_803e1560;
  local_350 = 0;
  local_364 = (undefined2)uVar5;
  local_37c = FLOAT_803e1530;
  local_378 = FLOAT_803e1530;
  local_374 = FLOAT_803e1530;
  local_388 = FLOAT_803e1530;
  local_384 = FLOAT_803e1530;
  local_380 = FLOAT_803e1530;
  local_370 = FLOAT_803e1564;
  local_368 = 1;
  local_36c = 0;
  local_34f = 3;
  local_34e = 0;
  local_34d = 0;
  iVar1 = (int)puVar2 + (0xd8 - (int)&local_348);
  iVar1 = iVar1 / 0x18 + (iVar1 >> 0x1f);
  local_34b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_362 = DAT_80318e10;
  local_360 = DAT_80318e12;
  local_35e = DAT_80318e14;
  local_35c = DAT_80318e16;
  local_35a = DAT_80318e18;
  local_358 = DAT_80318e1a;
  local_356 = DAT_80318e1c;
  local_3a8 = &local_348;
  local_354 = param_4 | 0x4000400;
  if ((param_4 & 1) != 0) {
    if ((local_3a4 == 0) || (param_3 == 0)) {
      if (local_3a4 == 0) {
        if (param_3 != 0) {
          local_37c = FLOAT_803e1530 + *(float *)(param_3 + 0xc);
          local_378 = FLOAT_803e1530 + *(float *)(param_3 + 0x10);
          local_374 = FLOAT_803e1530 + *(float *)(param_3 + 0x14);
        }
      }
      else {
        local_37c = FLOAT_803e1530 + *(float *)(local_3a4 + 0x18);
        local_378 = FLOAT_803e1530 + *(float *)(local_3a4 + 0x1c);
        local_374 = FLOAT_803e1530 + *(float *)(local_3a4 + 0x20);
      }
    }
    else {
      local_37c = FLOAT_803e1530 + *(float *)(local_3a4 + 0x18) + *(float *)(param_3 + 0xc);
      local_378 = FLOAT_803e1530 + *(float *)(local_3a4 + 0x1c) + *(float *)(param_3 + 0x10);
      local_374 = FLOAT_803e1530 + *(float *)(local_3a4 + 0x20) + *(float *)(param_3 + 0x14);
    }
  }
  (**(code **)(*DAT_803dca7c + 8))(&local_3a8,0,3,&DAT_80318df0,1,&DAT_803db980,0x26a,0);
  __psq_l0(auStack8,uVar3);
  __psq_l1(auStack8,uVar3);
  FUN_80286124();
  return;
}

