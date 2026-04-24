// Function: FUN_800f7434
// Entry: 800f7434
// Size: 896 bytes

/* WARNING: Removing unreachable block (ram,0x800f778c) */
/* WARNING: Removing unreachable block (ram,0x800f7794) */

void FUN_800f7434(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)

{
  int iVar1;
  undefined4 uVar2;
  undefined8 in_f30;
  double dVar3;
  undefined8 in_f31;
  double dVar4;
  undefined8 uVar5;
  undefined4 *local_3b8;
  int local_3b4;
  float local_398;
  float local_394;
  float local_390;
  float local_38c;
  float local_388;
  float local_384;
  float local_380;
  undefined4 local_37c;
  undefined4 local_378;
  undefined2 local_374;
  undefined2 local_372;
  undefined2 local_370;
  undefined2 local_36e;
  undefined2 local_36c;
  undefined2 local_36a;
  undefined2 local_368;
  undefined2 local_366;
  uint local_364;
  undefined local_360;
  undefined local_35f;
  undefined local_35e;
  undefined local_35d;
  char local_35b;
  undefined4 local_358;
  float local_354;
  float local_350;
  float local_34c;
  undefined4 local_348;
  undefined2 local_344;
  undefined local_342;
  undefined4 local_340;
  float local_33c;
  float local_338;
  float local_334;
  undefined4 local_330;
  undefined2 local_32c;
  undefined local_32a;
  undefined4 local_328;
  float local_324;
  float local_320;
  float local_31c;
  undefined4 local_318;
  undefined2 local_314;
  undefined local_312;
  undefined4 local_310;
  float local_30c;
  float local_308;
  float local_304;
  undefined4 local_300;
  undefined2 local_2fc;
  undefined local_2fa;
  undefined4 local_2f8;
  float local_2f4;
  float local_2f0;
  float local_2ec;
  undefined4 local_2e8;
  undefined2 local_2e4;
  undefined local_2e2;
  undefined auStack736 [648];
  undefined4 local_58;
  uint uStack84;
  undefined4 local_50;
  uint uStack76;
  undefined4 local_48;
  uint uStack68;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar2 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar5 = FUN_802860dc();
  local_3b4 = (int)((ulonglong)uVar5 >> 0x20);
  iVar1 = (int)uVar5;
  dVar4 = (double)FLOAT_803e0fb0;
  dVar3 = (double)FLOAT_803e0fb4;
  local_344 = 100;
  if (iVar1 == 0) {
    dVar4 = (double)FLOAT_803e0fb8;
    dVar3 = (double)FLOAT_803e0fbc;
    local_344 = 0x410;
  }
  else if (iVar1 == 1) {
    dVar4 = (double)FLOAT_803e0fc0;
    dVar3 = (double)FLOAT_803e0fc4;
    local_344 = 0x410;
  }
  else if (iVar1 == 2) {
    dVar4 = (double)FLOAT_803e0fc8;
    dVar3 = (double)FLOAT_803e0fcc;
    local_344 = 0x410;
  }
  else if (iVar1 == 3) {
    dVar4 = (double)FLOAT_803e0fc8;
    dVar3 = (double)FLOAT_803e0fcc;
    local_344 = 0x410;
  }
  local_3b8 = &local_358;
  local_342 = 0;
  local_348 = 0;
  local_358 = 0x20000000;
  local_354 = FLOAT_803e0fd0;
  local_350 = (float)dVar4;
  local_34c = (float)dVar3;
  local_32a = 1;
  local_32c = 0;
  local_330 = 0;
  local_340 = 0x400000;
  uStack84 = FUN_800221a0(0xffffff9c,100);
  uStack84 = uStack84 ^ 0x80000000;
  local_58 = 0x43300000;
  local_33c = (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803e0fe0);
  local_338 = FLOAT_803e0fd4;
  uStack76 = FUN_800221a0(0xfffffb50,0xfffffce0);
  uStack76 = uStack76 ^ 0x80000000;
  local_50 = 0x43300000;
  local_334 = (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e0fe0);
  local_312 = 1;
  local_314 = 0;
  local_318 = 0;
  local_328 = 0x40000000;
  local_324 = local_33c;
  local_320 = FLOAT_803e0fd4;
  local_31c = local_338;
  local_2fa = 1;
  local_2fc = 0x65;
  local_300 = 0;
  local_310 = 0x800000;
  local_30c = FLOAT_803e0fd8;
  local_308 = FLOAT_803e0fd8;
  local_304 = FLOAT_803e0fd4;
  local_2e2 = 2;
  local_2e4 = 0;
  local_2e8 = 0;
  local_2f8 = 0x20000000;
  local_2f4 = FLOAT_803e0fd0;
  local_2f0 = (float)dVar4;
  local_2ec = (float)dVar3;
  local_360 = 0;
  local_374 = (undefined2)uVar5;
  uStack68 = FUN_800221a0(0xffffff9c,100);
  uStack68 = uStack68 ^ 0x80000000;
  local_48 = 0x43300000;
  local_38c = (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e0fe0);
  local_388 = FLOAT_803e0fd4;
  local_384 = FLOAT_803e0fd4;
  local_398 = FLOAT_803e0fd4;
  local_394 = FLOAT_803e0fd4;
  local_390 = FLOAT_803e0fd4;
  local_380 = FLOAT_803e0fd8;
  local_378 = 0;
  local_37c = 0;
  local_35f = 0;
  local_35e = 0;
  local_35d = 0;
  iVar1 = (int)(auStack736 + -(int)local_3b8) / 0x18 + ((int)(auStack736 + -(int)local_3b8) >> 0x1f)
  ;
  local_35b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_372 = DAT_80316020;
  local_370 = DAT_80316022;
  local_36e = DAT_80316024;
  local_36c = DAT_80316026;
  local_36a = DAT_80316028;
  local_368 = DAT_8031602a;
  local_366 = DAT_8031602c;
  local_364 = param_4 | 0x10400;
  if ((param_4 & 1) != 0) {
    if (local_3b4 == 0) {
      local_38c = local_38c + *(float *)(param_3 + 0xc);
      local_388 = FLOAT_803e0fd4 + *(float *)(param_3 + 0x10);
      local_384 = FLOAT_803e0fd4 + *(float *)(param_3 + 0x14);
    }
    else {
      local_38c = local_38c + *(float *)(local_3b4 + 0x18);
      local_388 = FLOAT_803e0fd4 + *(float *)(local_3b4 + 0x1c);
      local_384 = FLOAT_803e0fd4 + *(float *)(local_3b4 + 0x20);
    }
  }
  (**(code **)(*DAT_803dca7c + 8))(&local_3b8,0,0,0,0,0,0,0);
  __psq_l0(auStack8,uVar2);
  __psq_l1(auStack8,uVar2);
  __psq_l0(auStack24,uVar2);
  __psq_l1(auStack24,uVar2);
  FUN_80286128();
  return;
}

