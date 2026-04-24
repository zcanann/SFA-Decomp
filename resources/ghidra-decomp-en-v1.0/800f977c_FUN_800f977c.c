// Function: FUN_800f977c
// Entry: 800f977c
// Size: 1780 bytes

/* WARNING: Removing unreachable block (ram,0x800f9e50) */

void FUN_800f977c(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)

{
  int iVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 uVar4;
  undefined8 in_f31;
  double dVar5;
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
  uint uStack68;
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  undefined4 local_30;
  uint uStack44;
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar6 = FUN_802860d8();
  local_3a4 = (int)((ulonglong)uVar6 >> 0x20);
  iVar1 = (int)uVar6;
  if (iVar1 == 0) {
    local_332[0] = 0;
    local_334 = 3;
    local_338 = &DAT_803db918;
    local_348 = 8;
    iVar2 = FUN_800221a0(0,0x69);
    uStack68 = iVar2 + 0x8cU ^ 0x80000000;
    local_48 = 0x43300000;
    local_344 = (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e1170);
    iVar2 = FUN_800221a0(0,0x69);
    uStack60 = iVar2 + 0x8cU ^ 0x80000000;
    local_40 = 0x43300000;
    local_340 = (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e1170);
    iVar2 = FUN_800221a0(0,0x1e);
    uStack52 = iVar2 + 0xe1U ^ 0x80000000;
    local_38 = 0x43300000;
    local_33c = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e1170);
    puVar3 = (undefined4 *)(local_332 + 2);
  }
  else {
    puVar3 = &local_348;
    if (iVar1 == 1) {
      local_332[0] = 0;
      local_334 = 3;
      local_338 = &DAT_803db918;
      local_348 = 8;
      iVar2 = FUN_800221a0(0,0x1e);
      uStack52 = iVar2 + 0xe1U ^ 0x80000000;
      local_38 = 0x43300000;
      local_344 = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e1170);
      iVar2 = FUN_800221a0(0,0x69);
      uStack60 = iVar2 + 0x8cU ^ 0x80000000;
      local_40 = 0x43300000;
      local_340 = (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e1170);
      iVar2 = FUN_800221a0(0,0x41);
      uStack68 = iVar2 + 0x78U ^ 0x80000000;
      local_48 = 0x43300000;
      local_33c = (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e1170);
      puVar3 = (undefined4 *)(local_332 + 2);
    }
  }
  uStack52 = FUN_800221a0(0,0xfffe);
  uStack52 = uStack52 ^ 0x80000000;
  local_38 = 0x43300000;
  dVar5 = (double)(float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e1170);
  uStack60 = FUN_800221a0(0xfffff448,0xffffd120);
  uStack60 = uStack60 ^ 0x80000000;
  local_40 = 0x43300000;
  *(undefined *)((int)puVar3 + 0x16) = 0;
  *(undefined2 *)(puVar3 + 5) = 0;
  puVar3[4] = 0;
  *puVar3 = 0x80;
  puVar3[1] = FLOAT_803e1138;
  puVar3[2] = (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e1170);
  puVar3[3] = (float)dVar5;
  *(undefined *)((int)puVar3 + 0x2e) = 0;
  *(undefined2 *)(puVar3 + 0xb) = 3;
  puVar3[10] = &DAT_803db918;
  puVar3[6] = 4;
  puVar3[7] = FLOAT_803e1138;
  puVar3[8] = FLOAT_803e1138;
  puVar3[9] = FLOAT_803e1138;
  *(undefined *)((int)puVar3 + 0x46) = 0;
  *(undefined2 *)(puVar3 + 0x11) = 3;
  puVar3[0x10] = &DAT_803db918;
  puVar3[0xc] = 2;
  puVar3[0xd] = FLOAT_803e113c;
  uStack68 = FUN_800221a0(0,0x32);
  uStack68 = uStack68 ^ 0x80000000;
  local_48 = 0x43300000;
  puVar3[0xe] = FLOAT_803e1144 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e1170) +
                FLOAT_803e1140;
  uStack44 = FUN_800221a0(0,0x14);
  uStack44 = uStack44 ^ 0x80000000;
  local_30 = 0x43300000;
  puVar3[0xf] = FLOAT_803e1144 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e1170) +
                FLOAT_803e1148;
  *(undefined *)((int)puVar3 + 0x5e) = 1;
  *(undefined2 *)(puVar3 + 0x17) = 3;
  puVar3[0x16] = &DAT_803db918;
  puVar3[0x12] = 4;
  iVar2 = FUN_800221a0(0,10);
  if (iVar2 == 0) {
    uStack44 = FUN_800221a0(0,0x1e);
    uStack44 = uStack44 ^ 0x80000000;
    puVar3[0x13] = FLOAT_803e114c + (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e1170)
    ;
  }
  else {
    uStack44 = FUN_800221a0(0,10);
    uStack44 = uStack44 ^ 0x80000000;
    puVar3[0x13] = FLOAT_803e1150 + (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e1170)
    ;
  }
  local_30 = 0x43300000;
  puVar3[0x14] = FLOAT_803e1138;
  puVar3[0x15] = FLOAT_803e1138;
  *(undefined *)((int)puVar3 + 0x76) = 2;
  *(undefined2 *)(puVar3 + 0x1d) = 0;
  puVar3[0x1c] = 0;
  puVar3[0x18] = 0x80;
  puVar3[0x19] = FLOAT_803e1138;
  puVar3[0x1a] = FLOAT_803e1138;
  uStack44 = FUN_800221a0(0,0xfffe);
  uStack44 = uStack44 ^ 0x80000000;
  local_30 = 0x43300000;
  puVar3[0x1b] = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e1170);
  *(undefined *)((int)puVar3 + 0x8e) = 1;
  *(undefined2 *)(puVar3 + 0x23) = 3;
  puVar3[0x22] = &DAT_803db918;
  puVar3[0x1e] = 2;
  puVar3[0x1f] = FLOAT_803e1154;
  puVar3[0x20] = FLOAT_803e1158;
  puVar3[0x21] = FLOAT_803e115c;
  *(undefined *)((int)puVar3 + 0xa6) = 2;
  *(undefined2 *)(puVar3 + 0x29) = 0;
  puVar3[0x28] = 0;
  puVar3[0x24] = 0x80;
  puVar3[0x25] = FLOAT_803e1138;
  puVar3[0x26] = FLOAT_803e1138;
  uStack52 = FUN_800221a0(0,0xfffe);
  uStack52 = uStack52 ^ 0x80000000;
  local_38 = 0x43300000;
  puVar3[0x27] = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e1170);
  *(undefined *)((int)puVar3 + 0xbe) = 2;
  *(undefined2 *)(puVar3 + 0x2f) = 3;
  puVar3[0x2e] = &DAT_803db918;
  puVar3[0x2a] = 4;
  puVar3[0x2b] = FLOAT_803e1138;
  puVar3[0x2c] = FLOAT_803e1138;
  puVar3[0x2d] = FLOAT_803e1138;
  *(undefined *)((int)puVar3 + 0xd6) = 2;
  *(undefined2 *)(puVar3 + 0x35) = 3;
  puVar3[0x34] = &DAT_803db918;
  puVar3[0x30] = 2;
  puVar3[0x31] = FLOAT_803e1160;
  puVar3[0x32] = FLOAT_803e1164;
  puVar3[0x33] = FLOAT_803e1168;
  local_350 = 0;
  local_364 = (undefined2)uVar6;
  local_37c = FLOAT_803e1138;
  if (iVar1 == 0) {
    local_378 = FLOAT_803e1138;
  }
  else if (iVar1 == 1) {
    local_378 = FLOAT_803e116c;
  }
  local_374 = FLOAT_803e1138;
  local_388 = FLOAT_803e1138;
  local_384 = FLOAT_803e1138;
  local_380 = FLOAT_803e1138;
  local_370 = FLOAT_803e1164;
  local_368 = 1;
  local_36c = 0;
  local_34f = 3;
  local_34e = 0;
  local_34d = 0;
  iVar1 = (int)puVar3 + (0xd8 - (int)&local_348);
  iVar1 = iVar1 / 0x18 + (iVar1 >> 0x1f);
  local_34b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_362 = DAT_80316c60;
  local_360 = DAT_80316c62;
  local_35e = DAT_80316c64;
  local_35c = DAT_80316c66;
  local_35a = DAT_80316c68;
  local_358 = DAT_80316c6a;
  local_356 = DAT_80316c6c;
  local_3a8 = &local_348;
  local_354 = param_4 | 0x4000410;
  if ((param_4 & 1) != 0) {
    if ((local_3a4 == 0) || (param_3 == 0)) {
      if (local_3a4 == 0) {
        if (param_3 != 0) {
          local_37c = FLOAT_803e1138 + *(float *)(param_3 + 0xc);
          local_378 = local_378 + *(float *)(param_3 + 0x10);
          local_374 = FLOAT_803e1138 + *(float *)(param_3 + 0x14);
        }
      }
      else {
        local_37c = FLOAT_803e1138 + *(float *)(local_3a4 + 0x18);
        local_378 = local_378 + *(float *)(local_3a4 + 0x1c);
        local_374 = FLOAT_803e1138 + *(float *)(local_3a4 + 0x20);
      }
    }
    else {
      local_37c = FLOAT_803e1138 + *(float *)(local_3a4 + 0x18) + *(float *)(param_3 + 0xc);
      local_378 = local_378 + *(float *)(local_3a4 + 0x1c) + *(float *)(param_3 + 0x10);
      local_374 = FLOAT_803e1138 + *(float *)(local_3a4 + 0x20) + *(float *)(param_3 + 0x14);
    }
  }
  (**(code **)(*DAT_803dca7c + 8))(&local_3a8,0,3,&DAT_80316c40,1,&DAT_803db910,0x26a,0);
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  FUN_80286124();
  return;
}

