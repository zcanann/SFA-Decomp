// Function: FUN_800eb334
// Entry: 800eb334
// Size: 1408 bytes

/* WARNING: Removing unreachable block (ram,0x800eb894) */
/* WARNING: Removing unreachable block (ram,0x800eb88c) */
/* WARNING: Removing unreachable block (ram,0x800eb884) */
/* WARNING: Removing unreachable block (ram,0x800eb87c) */
/* WARNING: Removing unreachable block (ram,0x800eb874) */
/* WARNING: Removing unreachable block (ram,0x800eb86c) */
/* WARNING: Removing unreachable block (ram,0x800eb864) */
/* WARNING: Removing unreachable block (ram,0x800eb374) */
/* WARNING: Removing unreachable block (ram,0x800eb36c) */
/* WARNING: Removing unreachable block (ram,0x800eb364) */
/* WARNING: Removing unreachable block (ram,0x800eb35c) */
/* WARNING: Removing unreachable block (ram,0x800eb354) */
/* WARNING: Removing unreachable block (ram,0x800eb34c) */
/* WARNING: Removing unreachable block (ram,0x800eb344) */

void FUN_800eb334(undefined4 param_1,undefined4 param_2,int param_3,uint param_4,undefined4 param_5,
                 int *param_6)

{
  int iVar1;
  double dVar2;
  short sVar3;
  short sVar4;
  short sVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  undefined4 uVar9;
  undefined *puVar10;
  undefined4 uVar11;
  undefined *puVar12;
  int iVar13;
  int iVar14;
  double in_f25;
  double dVar15;
  double in_f26;
  double dVar16;
  double in_f27;
  double dVar17;
  double in_f28;
  double dVar18;
  double in_f29;
  double dVar19;
  double in_f30;
  double dVar20;
  double in_f31;
  double dVar21;
  double in_ps25_1;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar22;
  ushort local_468;
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
  uint uStack_ec;
  undefined4 local_e8;
  uint uStack_e4;
  undefined4 local_e0;
  uint uStack_dc;
  undefined4 local_d8;
  uint uStack_d4;
  undefined4 local_d0;
  uint uStack_cc;
  longlong local_c8;
  longlong local_c0;
  float local_68;
  float fStack_64;
  float local_58;
  float fStack_54;
  float local_48;
  float fStack_44;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  local_58 = (float)in_f26;
  fStack_54 = (float)in_ps26_1;
  local_68 = (float)in_f25;
  fStack_64 = (float)in_ps25_1;
  uVar22 = FUN_80286810();
  iVar6 = (int)((ulonglong)uVar22 >> 0x20);
  iVar8 = (int)uVar22;
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
  dVar17 = (double)FLOAT_803e1390;
  dVar18 = (double)FLOAT_803e1394;
  dVar19 = (double)FLOAT_803e1398;
  dVar20 = (double)FLOAT_803e139c;
  dVar21 = (double)FLOAT_803e13a0;
  dVar16 = DOUBLE_803e13a8;
  for (iVar14 = 0; iVar14 < iVar13; iVar14 = iVar14 + 1) {
    if (iVar8 == 0) {
      uVar7 = FUN_80022264(0xffffffe5,0x1b);
      sVar3 = sVar3 + (short)uVar7;
      if (sVar3 < 0x100) {
        if (sVar3 < 0) {
          sVar3 = 0;
        }
      }
      else {
        sVar3 = 0xff;
      }
      uVar7 = FUN_80022264(0xffffffe5,0x1b);
      sVar4 = sVar4 + (short)uVar7;
      if (sVar4 < 0x100) {
        if (sVar4 < 0) {
          sVar4 = 0;
        }
      }
      else {
        sVar4 = 0xff;
      }
      uVar7 = FUN_80022264(0xffffffe5,0x1b);
      sVar5 = sVar5 + (short)uVar7;
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
    if (iVar8 == 0) {
      local_3dc = 3;
      local_3e0 = &DAT_803dc500;
    }
    else {
      local_3dc = 4;
      local_3e0 = &DAT_803dc508;
    }
    local_3f0 = 8;
    uStack_ec = (int)sVar3 ^ 0x80000000;
    local_f0 = 0x43300000;
    local_3ec = (float)((double)CONCAT44(0x43300000,uStack_ec) - dVar16);
    uStack_e4 = (int)sVar4 ^ 0x80000000;
    local_e8 = 0x43300000;
    local_3e8 = (float)((double)CONCAT44(0x43300000,uStack_e4) - dVar16);
    uStack_dc = (int)sVar5 ^ 0x80000000;
    local_e0 = 0x43300000;
    local_3e4 = (float)((double)CONCAT44(0x43300000,uStack_dc) - dVar16);
    uStack_d4 = FUN_80022264(0,0xfffe);
    uStack_d4 = uStack_d4 ^ 0x80000000;
    local_d8 = 0x43300000;
    dVar15 = (double)(float)((double)CONCAT44(0x43300000,uStack_d4) - dVar16);
    uStack_cc = FUN_80022264(0xfffff448,0xffffd120);
    uStack_cc = uStack_cc ^ 0x80000000;
    local_d0 = 0x43300000;
    dVar2 = (double)CONCAT44(0x43300000,uStack_cc) - dVar16;
    local_3d0 = (float)dVar2;
    local_3c2 = 0;
    local_3c4 = 0;
    local_3c8 = 0;
    local_3d8 = 0x80;
    local_3d4 = (float)dVar17;
    local_3cc = (float)dVar15;
    local_3aa = 0;
    if (iVar8 == 0) {
      local_3ac = 3;
      local_3b0 = &DAT_803dc500;
    }
    else {
      local_3ac = 4;
      local_3b0 = &DAT_803dc508;
    }
    local_3c0 = 2;
    local_3bc = (float)dVar18;
    local_3b8 = (float)dVar19;
    local_3b4 = (float)dVar20;
    local_392 = 1;
    local_394 = 0;
    local_398 = 0;
    local_3a8 = 0x400000;
    local_3a4 = (float)dVar17;
    local_3a0 = (float)dVar17;
    local_39c = (float)dVar21;
    local_45c = (float)dVar17;
    local_458 = (float)dVar17;
    local_454 = (float)dVar17;
    local_460 = (float)dVar18;
    local_464 = 0;
    iVar1 = (int)dVar2;
    local_c8 = (longlong)iVar1;
    local_466 = (undefined2)iVar1;
    local_c0 = (longlong)(int)dVar15;
    local_468 = (ushort)(int)dVar15;
    FUN_80021b8c(&local_468,&local_3a4);
    local_3f8 = 0;
    local_424 = (float)dVar17;
    local_420 = (float)dVar17;
    local_41c = (float)dVar17;
    local_430 = (float)dVar17;
    local_42c = (float)dVar17;
    local_428 = (float)dVar17;
    local_418 = (float)dVar18;
    local_410 = 1;
    local_414 = 0;
    if (iVar8 == 0) {
      local_3f7 = 3;
    }
    else {
      local_3f7 = 4;
    }
    local_3f6 = 0;
    local_3f5 = 0x10;
    local_3f3 = 4;
    local_40a = DAT_80312a4c;
    local_408 = DAT_80312a4e;
    local_406 = DAT_80312a50;
    local_404 = DAT_80312a52;
    local_402 = DAT_80312a54;
    local_400 = DAT_80312a56;
    local_3fe = DAT_80312a58;
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
    if (iVar8 == 0) {
      puVar12 = &DAT_803dc4f8;
      uVar11 = 1;
      puVar10 = (undefined *)0x803129f8;
    }
    else {
      puVar12 = &DAT_80312a40;
      uVar11 = 2;
      puVar10 = &DAT_80312a18;
    }
    if (iVar8 == 0) {
      uVar9 = 3;
    }
    else {
      uVar9 = 4;
    }
    local_450 = &local_3f0;
    local_44c = iVar6;
    local_40c = (short)uVar22;
    local_3fc = param_4 | 0x2000490;
    (**(code **)(*DAT_803dd6fc + 8))(&local_450,0,uVar9,puVar10,uVar11,puVar12,0,0);
  }
  FUN_8028685c();
  return;
}

