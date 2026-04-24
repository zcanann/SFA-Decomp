// Function: FUN_800f76d0
// Entry: 800f76d0
// Size: 896 bytes

/* WARNING: Removing unreachable block (ram,0x800f7a30) */
/* WARNING: Removing unreachable block (ram,0x800f7a28) */
/* WARNING: Removing unreachable block (ram,0x800f76e8) */
/* WARNING: Removing unreachable block (ram,0x800f76e0) */

void FUN_800f76d0(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)

{
  int iVar1;
  double in_f30;
  double dVar2;
  double in_f31;
  double dVar3;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar4;
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
  undefined auStack_2e0 [648];
  undefined4 local_58;
  uint uStack_54;
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar4 = FUN_80286840();
  local_3b4 = (int)((ulonglong)uVar4 >> 0x20);
  iVar1 = (int)uVar4;
  dVar3 = (double)FLOAT_803e1c30;
  dVar2 = (double)FLOAT_803e1c34;
  local_344 = 100;
  if (iVar1 == 0) {
    dVar3 = (double)FLOAT_803e1c38;
    dVar2 = (double)FLOAT_803e1c3c;
    local_344 = 0x410;
  }
  else if (iVar1 == 1) {
    dVar3 = (double)FLOAT_803e1c40;
    dVar2 = (double)FLOAT_803e1c44;
    local_344 = 0x410;
  }
  else if (iVar1 == 2) {
    dVar3 = (double)FLOAT_803e1c48;
    dVar2 = (double)FLOAT_803e1c4c;
    local_344 = 0x410;
  }
  else if (iVar1 == 3) {
    dVar3 = (double)FLOAT_803e1c48;
    dVar2 = (double)FLOAT_803e1c4c;
    local_344 = 0x410;
  }
  local_342 = 0;
  local_348 = 0;
  local_358 = 0x20000000;
  local_354 = FLOAT_803e1c50;
  local_350 = (float)dVar3;
  local_34c = (float)dVar2;
  local_32a = 1;
  local_32c = 0;
  local_330 = 0;
  local_340 = 0x400000;
  uStack_54 = FUN_80022264(0xffffff9c,100);
  uStack_54 = uStack_54 ^ 0x80000000;
  local_58 = 0x43300000;
  local_33c = (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e1c60);
  local_338 = FLOAT_803e1c54;
  uStack_4c = FUN_80022264(0xfffffb50,0xfffffce0);
  uStack_4c = uStack_4c ^ 0x80000000;
  local_50 = 0x43300000;
  local_334 = (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1c60);
  local_312 = 1;
  local_314 = 0;
  local_318 = 0;
  local_328 = 0x40000000;
  local_324 = local_33c;
  local_320 = FLOAT_803e1c54;
  local_31c = local_338;
  local_2fa = 1;
  local_2fc = 0x65;
  local_300 = 0;
  local_310 = 0x800000;
  local_30c = FLOAT_803e1c58;
  local_308 = FLOAT_803e1c58;
  local_304 = FLOAT_803e1c54;
  local_2e2 = 2;
  local_2e4 = 0;
  local_2e8 = 0;
  local_2f8 = 0x20000000;
  local_2f4 = FLOAT_803e1c50;
  local_2f0 = (float)dVar3;
  local_2ec = (float)dVar2;
  local_360 = 0;
  local_374 = (undefined2)uVar4;
  uStack_44 = FUN_80022264(0xffffff9c,100);
  uStack_44 = uStack_44 ^ 0x80000000;
  local_48 = 0x43300000;
  local_38c = (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e1c60);
  local_388 = FLOAT_803e1c54;
  local_384 = FLOAT_803e1c54;
  local_398 = FLOAT_803e1c54;
  local_394 = FLOAT_803e1c54;
  local_390 = FLOAT_803e1c54;
  local_380 = FLOAT_803e1c58;
  local_378 = 0;
  local_37c = 0;
  local_35f = 0;
  local_35e = 0;
  local_35d = 0;
  iVar1 = (int)(auStack_2e0 + -(int)&local_358) / 0x18 +
          ((int)(auStack_2e0 + -(int)&local_358) >> 0x1f);
  local_35b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_372 = DAT_80316c70;
  local_370 = DAT_80316c72;
  local_36e = DAT_80316c74;
  local_36c = DAT_80316c76;
  local_36a = DAT_80316c78;
  local_368 = DAT_80316c7a;
  local_366 = DAT_80316c7c;
  local_364 = param_4 | 0x10400;
  if ((param_4 & 1) != 0) {
    if (local_3b4 == 0) {
      local_38c = local_38c + *(float *)(param_3 + 0xc);
      local_388 = FLOAT_803e1c54 + *(float *)(param_3 + 0x10);
      local_384 = FLOAT_803e1c54 + *(float *)(param_3 + 0x14);
    }
    else {
      local_38c = local_38c + *(float *)(local_3b4 + 0x18);
      local_388 = FLOAT_803e1c54 + *(float *)(local_3b4 + 0x1c);
      local_384 = FLOAT_803e1c54 + *(float *)(local_3b4 + 0x20);
    }
  }
  local_3b8 = &local_358;
  (**(code **)(*DAT_803dd6fc + 8))(&local_3b8,0,0,0,0,0,0,0);
  FUN_8028688c();
  return;
}

