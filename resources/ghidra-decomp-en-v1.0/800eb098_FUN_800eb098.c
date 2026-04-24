// Function: FUN_800eb098
// Entry: 800eb098
// Size: 1408 bytes

/* WARNING: Removing unreachable block (ram,0x800eb5f0) */
/* WARNING: Removing unreachable block (ram,0x800eb5e0) */
/* WARNING: Removing unreachable block (ram,0x800eb5d0) */
/* WARNING: Removing unreachable block (ram,0x800eb5c8) */
/* WARNING: Removing unreachable block (ram,0x800eb5d8) */
/* WARNING: Removing unreachable block (ram,0x800eb5e8) */
/* WARNING: Removing unreachable block (ram,0x800eb5f8) */

void FUN_800eb098(undefined4 param_1,undefined4 param_2,int param_3,uint param_4,undefined4 param_5,
                 int *param_6)

{
  int iVar1;
  double dVar2;
  short sVar3;
  short sVar4;
  short sVar5;
  int iVar6;
  undefined4 uVar7;
  short sVar8;
  int iVar9;
  undefined4 uVar10;
  undefined *puVar11;
  undefined *puVar12;
  int iVar13;
  int iVar14;
  undefined4 uVar15;
  undefined8 in_f25;
  double dVar16;
  undefined8 in_f26;
  double dVar17;
  undefined8 in_f27;
  double dVar18;
  undefined8 in_f28;
  double dVar19;
  undefined8 in_f29;
  double dVar20;
  undefined8 in_f30;
  double dVar21;
  undefined8 in_f31;
  double dVar22;
  undefined8 uVar23;
  undefined2 local_468;
  undefined2 local_466;
  undefined2 local_464;
  float local_460;
  float local_45c;
  float local_458;
  float local_454;
  undefined4 *local_450;
  int local_44c;
  float local_430;
  float local_42c;
  float local_428;
  float local_424;
  float local_420;
  float local_41c;
  float local_418;
  undefined4 local_414;
  undefined4 local_410;
  undefined2 local_40c;
  undefined2 local_40a;
  undefined2 local_408;
  undefined2 local_406;
  undefined2 local_404;
  undefined2 local_402;
  undefined2 local_400;
  undefined2 local_3fe;
  uint local_3fc;
  undefined local_3f8;
  undefined local_3f7;
  undefined local_3f6;
  undefined local_3f5;
  undefined local_3f3;
  undefined4 local_3f0;
  float local_3ec;
  float local_3e8;
  float local_3e4;
  undefined *local_3e0;
  undefined2 local_3dc;
  undefined local_3da;
  undefined4 local_3d8;
  float local_3d4;
  float local_3d0;
  float local_3cc;
  undefined4 local_3c8;
  undefined2 local_3c4;
  undefined local_3c2;
  undefined4 local_3c0;
  float local_3bc;
  float local_3b8;
  float local_3b4;
  undefined *local_3b0;
  undefined2 local_3ac;
  undefined local_3aa;
  undefined4 local_3a8;
  float local_3a4;
  float local_3a0;
  float local_39c;
  undefined4 local_398;
  undefined2 local_394;
  undefined local_392;
  undefined4 local_f0;
  uint uStack236;
  undefined4 local_e8;
  uint uStack228;
  undefined4 local_e0;
  uint uStack220;
  undefined4 local_d8;
  uint uStack212;
  undefined4 local_d0;
  uint uStack204;
  longlong local_c8;
  longlong local_c0;
  undefined auStack104 [16];
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar15 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  __psq_st0(auStack72,(int)((ulonglong)in_f27 >> 0x20),0);
  __psq_st1(auStack72,(int)in_f27,0);
  __psq_st0(auStack88,(int)((ulonglong)in_f26 >> 0x20),0);
  __psq_st1(auStack88,(int)in_f26,0);
  __psq_st0(auStack104,(int)((ulonglong)in_f25 >> 0x20),0);
  __psq_st1(auStack104,(int)in_f25,0);
  uVar23 = FUN_802860ac();
  iVar6 = (int)((ulonglong)uVar23 >> 0x20);
  iVar9 = (int)uVar23;
  uVar7 = 0;
  sVar3 = 0xff;
  sVar4 = 0xff;
  sVar5 = 0xff;
  iVar13 = 1;
  if (param_6 != (int *)0x0) {
    iVar13 = *param_6;
    sVar3 = (short)param_6[1];
    sVar4 = (short)param_6[2];
    sVar5 = (short)param_6[3];
  }
  dVar18 = (double)FLOAT_803e0710;
  dVar19 = (double)FLOAT_803e0714;
  dVar20 = (double)FLOAT_803e0718;
  dVar21 = (double)FLOAT_803e071c;
  dVar22 = (double)FLOAT_803e0720;
  dVar17 = DOUBLE_803e0728;
  for (iVar14 = 0; iVar14 < iVar13; iVar14 = iVar14 + 1) {
    if (iVar9 == 0) {
      sVar8 = FUN_800221a0(0xffffffe5,0x1b);
      sVar3 = sVar3 + sVar8;
      if (sVar3 < 0x100) {
        if (sVar3 < 0) {
          sVar3 = 0;
        }
      }
      else {
        sVar3 = 0xff;
      }
      sVar8 = FUN_800221a0(0xffffffe5,0x1b);
      sVar4 = sVar4 + sVar8;
      if (sVar4 < 0x100) {
        if (sVar4 < 0) {
          sVar4 = 0;
        }
      }
      else {
        sVar4 = 0xff;
      }
      sVar8 = FUN_800221a0(0xffffffe5,0x1b);
      sVar5 = sVar5 + sVar8;
      if (sVar5 < 0x100) {
        if (sVar5 < 0) {
          sVar5 = 0;
        }
      }
      else {
        sVar5 = 0xff;
      }
    }
    local_3da = 0;
    if (iVar9 == 0) {
      local_3dc = 3;
      local_3e0 = &DAT_803db8a0;
    }
    else {
      local_3dc = 4;
      local_3e0 = &DAT_803db8a8;
    }
    local_3f0 = 8;
    uStack236 = (int)sVar3 ^ 0x80000000;
    local_f0 = 0x43300000;
    local_3ec = (float)((double)CONCAT44(0x43300000,uStack236) - dVar17);
    uStack228 = (int)sVar4 ^ 0x80000000;
    local_e8 = 0x43300000;
    local_3e8 = (float)((double)CONCAT44(0x43300000,uStack228) - dVar17);
    uStack220 = (int)sVar5 ^ 0x80000000;
    local_e0 = 0x43300000;
    local_3e4 = (float)((double)CONCAT44(0x43300000,uStack220) - dVar17);
    uStack212 = FUN_800221a0(0,0xfffe);
    uStack212 = uStack212 ^ 0x80000000;
    local_d8 = 0x43300000;
    dVar16 = (double)(float)((double)CONCAT44(0x43300000,uStack212) - dVar17);
    uStack204 = FUN_800221a0(0xfffff448,0xffffd120);
    uStack204 = uStack204 ^ 0x80000000;
    local_d0 = 0x43300000;
    dVar2 = (double)CONCAT44(0x43300000,uStack204) - dVar17;
    local_3d0 = (float)dVar2;
    local_3c2 = 0;
    local_3c4 = 0;
    local_3c8 = 0;
    local_3d8 = 0x80;
    local_3d4 = (float)dVar18;
    local_3cc = (float)dVar16;
    local_3aa = 0;
    if (iVar9 == 0) {
      local_3ac = 3;
      local_3b0 = &DAT_803db8a0;
    }
    else {
      local_3ac = 4;
      local_3b0 = &DAT_803db8a8;
    }
    local_3c0 = 2;
    local_3bc = (float)dVar19;
    local_3b8 = (float)dVar20;
    local_3b4 = (float)dVar21;
    local_392 = 1;
    local_394 = 0;
    local_398 = 0;
    local_3a8 = 0x400000;
    local_3a4 = (float)dVar18;
    local_3a0 = (float)dVar18;
    local_39c = (float)dVar22;
    local_45c = (float)dVar18;
    local_458 = (float)dVar18;
    local_454 = (float)dVar18;
    local_460 = (float)dVar19;
    local_464 = 0;
    iVar1 = (int)dVar2;
    local_c8 = (longlong)iVar1;
    local_466 = (undefined2)iVar1;
    local_c0 = (longlong)(int)dVar16;
    local_468 = (undefined2)(int)dVar16;
    FUN_80021ac8(&local_468,&local_3a4);
    local_3f8 = 0;
    local_424 = (float)dVar18;
    local_420 = (float)dVar18;
    local_41c = (float)dVar18;
    local_430 = (float)dVar18;
    local_42c = (float)dVar18;
    local_428 = (float)dVar18;
    local_418 = (float)dVar19;
    local_410 = 1;
    local_414 = 0;
    if (iVar9 == 0) {
      local_3f7 = 3;
    }
    else {
      local_3f7 = 4;
    }
    local_3f6 = 0;
    local_3f5 = 0x10;
    local_3f3 = 4;
    local_40a = DAT_80311dfc;
    local_408 = DAT_80311dfe;
    local_406 = DAT_80311e00;
    local_404 = DAT_80311e02;
    local_402 = DAT_80311e04;
    local_400 = DAT_80311e06;
    local_3fe = DAT_80311e08;
    if ((param_4 & 1) != 0) {
      if ((iVar6 == 0) || (param_3 == 0)) {
        if (iVar6 == 0) {
          if (param_3 != 0) {
            local_424 = local_424 + *(float *)(param_3 + 0xc);
            local_420 = local_420 + *(float *)(param_3 + 0x10);
            local_41c = local_41c + *(float *)(param_3 + 0x14);
          }
        }
        else {
          local_424 = local_424 + *(float *)(iVar6 + 0x18);
          local_420 = local_420 + *(float *)(iVar6 + 0x1c);
          local_41c = local_41c + *(float *)(iVar6 + 0x20);
        }
      }
      else {
        local_424 = local_424 + *(float *)(iVar6 + 0x18) + *(float *)(param_3 + 0xc);
        local_420 = local_420 + *(float *)(iVar6 + 0x1c) + *(float *)(param_3 + 0x10);
        local_41c = local_41c + *(float *)(iVar6 + 0x20) + *(float *)(param_3 + 0x14);
      }
    }
    if (iVar9 == 0) {
      puVar12 = &DAT_803db898;
      uVar7 = 1;
      puVar11 = (undefined *)0x80311da8;
    }
    else {
      puVar12 = &DAT_80311df0;
      uVar7 = 2;
      puVar11 = &DAT_80311dc8;
    }
    if (iVar9 == 0) {
      uVar10 = 3;
    }
    else {
      uVar10 = 4;
    }
    local_450 = &local_3f0;
    local_44c = iVar6;
    local_40c = (short)uVar23;
    local_3fc = param_4 | 0x2000490;
    uVar7 = (**(code **)(*DAT_803dca7c + 8))(&local_450,0,uVar10,puVar11,uVar7,puVar12,0,0);
  }
  __psq_l0(auStack8,uVar15);
  __psq_l1(auStack8,uVar15);
  __psq_l0(auStack24,uVar15);
  __psq_l1(auStack24,uVar15);
  __psq_l0(auStack40,uVar15);
  __psq_l1(auStack40,uVar15);
  __psq_l0(auStack56,uVar15);
  __psq_l1(auStack56,uVar15);
  __psq_l0(auStack72,uVar15);
  __psq_l1(auStack72,uVar15);
  __psq_l0(auStack88,uVar15);
  __psq_l1(auStack88,uVar15);
  __psq_l0(auStack104,uVar15);
  __psq_l1(auStack104,uVar15);
  FUN_802860f8(uVar7);
  return;
}

