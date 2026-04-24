// Function: FUN_800eb8b4
// Entry: 800eb8b4
// Size: 4516 bytes

/* WARNING: Removing unreachable block (ram,0x800eca38) */
/* WARNING: Removing unreachable block (ram,0x800eca30) */
/* WARNING: Removing unreachable block (ram,0x800eca28) */
/* WARNING: Removing unreachable block (ram,0x800eca20) */
/* WARNING: Removing unreachable block (ram,0x800eb8dc) */
/* WARNING: Removing unreachable block (ram,0x800eb8d4) */
/* WARNING: Removing unreachable block (ram,0x800eb8cc) */
/* WARNING: Removing unreachable block (ram,0x800eb8c4) */

void FUN_800eb8b4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,uint param_12,
                 undefined4 param_13,undefined4 *param_14,undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  int *piVar7;
  int iVar8;
  undefined4 *puVar9;
  undefined8 extraout_f1;
  double in_f28;
  double dVar10;
  double in_f29;
  double dVar11;
  double in_f30;
  double dVar12;
  double in_f31;
  double dVar13;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar14;
  undefined4 local_418;
  ushort local_414;
  undefined2 local_412;
  undefined2 local_410;
  float local_40c;
  float local_408;
  float local_404;
  float local_400;
  undefined4 *local_3fc;
  int local_3f8;
  float local_3dc;
  float local_3d8;
  float local_3d4;
  float local_3d0;
  float local_3cc;
  float local_3c8;
  float local_3c4;
  undefined4 local_3c0;
  undefined4 local_3bc;
  undefined2 local_3b8;
  undefined2 local_3b6;
  undefined2 local_3b4;
  undefined2 local_3b2;
  undefined2 local_3b0;
  undefined2 local_3ae;
  undefined2 local_3ac;
  undefined2 local_3aa;
  uint local_3a8;
  undefined local_3a4;
  undefined local_3a3;
  undefined local_3a2;
  undefined local_3a1;
  char local_39f;
  undefined4 local_39c;
  float local_398;
  float local_394;
  float local_390;
  undefined *local_38c;
  undefined2 local_388;
  undefined local_386;
  undefined4 local_384;
  float local_380;
  float local_37c;
  float local_378;
  undefined *local_374;
  undefined2 local_370;
  undefined local_36e;
  undefined4 local_36c;
  float local_368;
  float local_364;
  float local_360;
  undefined *local_35c;
  undefined2 local_358;
  undefined local_356 [2];
  undefined4 local_354 [5];
  undefined local_33e [678];
  undefined4 local_98;
  uint uStack_94;
  undefined4 local_90;
  uint uStack_8c;
  undefined4 local_88;
  uint uStack_84;
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
  uVar14 = FUN_80286820();
  iVar2 = (int)((ulonglong)uVar14 >> 0x20);
  uVar6 = (uint)uVar14;
  piVar7 = *(int **)(*(int *)(iVar2 + 0x7c) + *(char *)(iVar2 + 0xad) * 4);
  local_418 = DAT_803e13b0;
  if (param_14 != (undefined4 *)0x0) {
    local_418 = *param_14;
  }
  if (iVar2 == 0) {
    FUN_80137c30(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 s______This_modgfx_needs_an_owner_o_80312af0,piVar7,param_11,param_12,param_13,
                 param_14,param_15,param_16);
  }
  else {
    local_408 = FLOAT_803e13b4;
    local_404 = FLOAT_803e13b4;
    local_400 = FLOAT_803e13b4;
    local_40c = FLOAT_803e13b8;
    local_410 = 0;
    iVar8 = *piVar7;
    if (*(char *)(iVar8 + 0xf2) != '\0') {
      local_3a4 = (undefined)uVar14;
      local_3b8 = (undefined2)uVar14;
      local_3d0 = FLOAT_803e13b4;
      local_3cc = FLOAT_803e13b4;
      local_3c8 = FLOAT_803e13b4;
      local_3dc = FLOAT_803e13b4;
      local_3d8 = FLOAT_803e13b4;
      local_3d4 = FLOAT_803e13b4;
      local_3c4 = FLOAT_803e13b8;
      local_3bc = 1;
      local_3c0 = 0;
      local_3a3 = 4;
      local_3a2 = 0;
      local_3a1 = 0;
      local_3b6 = DAT_80312ac0;
      local_3b4 = DAT_80312ac2;
      local_3b2 = DAT_80312ac4;
      local_3b0 = DAT_80312ac6;
      local_3ae = DAT_80312ac8;
      local_3ac = DAT_80312aca;
      local_3aa = DAT_80312acc;
      local_3f8 = iVar2;
      uVar3 = FUN_80022264((int)local_418._0_2_,(int)local_418._2_2_);
      if (uVar6 == 0xc) {
        uVar3 = FUN_80022264(2,6);
      }
      else if (uVar6 == 0xd) {
        uVar3 = FUN_80022264(2,6);
      }
      else if (uVar6 == 0x11) {
        uVar3 = 5;
      }
      dVar10 = (double)FLOAT_803e13b4;
      dVar11 = (double)FLOAT_803e13cc;
      dVar13 = (double)FLOAT_803e13d0;
      dVar12 = DOUBLE_803e13d8;
      for (; uVar3 != 0; uVar3 = uVar3 - 1) {
        uVar4 = FUN_8005383c(**(uint **)(iVar8 + 0x20));
        local_386 = 0;
        local_388 = 1;
        local_38c = &DAT_803dc510;
        local_39c = 8;
        local_398 = (float)dVar10;
        local_394 = (float)dVar10;
        local_390 = (float)dVar10;
        if ((uVar6 == 0xc) || (uVar6 == 5)) {
          local_36e = 0;
          local_370 = 4;
          local_374 = &DAT_803dc514;
          local_384 = 2;
          uStack_94 = FUN_80022264(1,6);
          uStack_94 = uStack_94 ^ 0x80000000;
          local_98 = 0x43300000;
          local_380 = FLOAT_803e13bc *
                      (float)((double)CONCAT44(0x43300000,uStack_94) - DOUBLE_803e13d8);
          uStack_8c = FUN_80022264(1,6);
          uStack_8c = uStack_8c ^ 0x80000000;
          local_90 = 0x43300000;
          local_37c = FLOAT_803e13bc *
                      (float)((double)CONCAT44(0x43300000,uStack_8c) - DOUBLE_803e13d8);
          uStack_84 = FUN_80022264(1,6);
          uStack_84 = uStack_84 ^ 0x80000000;
          local_88 = 0x43300000;
          local_378 = FLOAT_803e13bc *
                      (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e13d8);
          puVar9 = &local_36c;
        }
        else if (uVar6 == 0xd) {
          local_36e = 0;
          local_370 = 4;
          local_374 = &DAT_803dc514;
          local_384 = 2;
          uStack_84 = FUN_80022264(1,6);
          uStack_84 = uStack_84 ^ 0x80000000;
          local_88 = 0x43300000;
          local_380 = FLOAT_803e13bc *
                      (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e13d8);
          uStack_8c = FUN_80022264(1,6);
          uStack_8c = uStack_8c ^ 0x80000000;
          local_90 = 0x43300000;
          local_37c = FLOAT_803e13bc *
                      (float)((double)CONCAT44(0x43300000,uStack_8c) - DOUBLE_803e13d8);
          uStack_94 = FUN_80022264(1,6);
          uStack_94 = uStack_94 ^ 0x80000000;
          local_98 = 0x43300000;
          local_378 = FLOAT_803e13bc *
                      (float)((double)CONCAT44(0x43300000,uStack_94) - DOUBLE_803e13d8);
          puVar9 = &local_36c;
        }
        else if (uVar6 == 0x14) {
          local_36e = 0;
          local_370 = 4;
          local_374 = &DAT_803dc514;
          local_384 = 2;
          uStack_84 = FUN_80022264(3,6);
          uStack_84 = uStack_84 ^ 0x80000000;
          local_88 = 0x43300000;
          local_380 = FLOAT_803e13c0 *
                      (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e13d8);
          uStack_8c = FUN_80022264(3,6);
          uStack_8c = uStack_8c ^ 0x80000000;
          local_90 = 0x43300000;
          local_37c = FLOAT_803e13c0 *
                      (float)((double)CONCAT44(0x43300000,uStack_8c) - DOUBLE_803e13d8);
          uStack_94 = FUN_80022264(3,6);
          uStack_94 = uStack_94 ^ 0x80000000;
          local_98 = 0x43300000;
          local_378 = FLOAT_803e13c0 *
                      (float)((double)CONCAT44(0x43300000,uStack_94) - DOUBLE_803e13d8);
          puVar9 = &local_36c;
        }
        else if (uVar6 == 0x11) {
          local_36e = 0;
          local_370 = 4;
          local_374 = &DAT_803dc514;
          local_384 = 2;
          uStack_84 = FUN_80022264(3,6);
          uStack_84 = uStack_84 ^ 0x80000000;
          local_88 = 0x43300000;
          local_380 = FLOAT_803e13c0 *
                      (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e13d8);
          uStack_8c = FUN_80022264(3,6);
          uStack_8c = uStack_8c ^ 0x80000000;
          local_90 = 0x43300000;
          local_37c = FLOAT_803e13c0 *
                      (float)((double)CONCAT44(0x43300000,uStack_8c) - DOUBLE_803e13d8);
          uStack_94 = FUN_80022264(3,6);
          uStack_94 = uStack_94 ^ 0x80000000;
          local_98 = 0x43300000;
          local_378 = FLOAT_803e13c0 *
                      (float)((double)CONCAT44(0x43300000,uStack_94) - DOUBLE_803e13d8);
          puVar9 = &local_36c;
        }
        else if (uVar6 == 0x10) {
          local_36e = 0;
          local_370 = 4;
          local_374 = &DAT_803dc514;
          local_384 = 8;
          local_380 = FLOAT_803e13c4;
          local_37c = (float)dVar10;
          local_378 = FLOAT_803e13c4;
          local_356[0] = 0;
          local_358 = 4;
          local_35c = &DAT_803dc514;
          local_36c = 2;
          uStack_84 = FUN_80022264(3,6);
          uStack_84 = uStack_84 ^ 0x80000000;
          local_88 = 0x43300000;
          local_368 = FLOAT_803e13c8 *
                      (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e13d8);
          uStack_8c = FUN_80022264(3,6);
          uStack_8c = uStack_8c ^ 0x80000000;
          local_90 = 0x43300000;
          local_364 = FLOAT_803e13c8 *
                      (float)((double)CONCAT44(0x43300000,uStack_8c) - DOUBLE_803e13d8);
          uStack_94 = FUN_80022264(3,6);
          uStack_94 = uStack_94 ^ 0x80000000;
          local_98 = 0x43300000;
          local_360 = FLOAT_803e13c8 *
                      (float)((double)CONCAT44(0x43300000,uStack_94) - DOUBLE_803e13d8);
          puVar9 = (undefined4 *)(local_356 + 2);
        }
        else {
          local_36e = 0;
          local_370 = 4;
          local_374 = &DAT_803dc514;
          local_384 = 2;
          uStack_84 = FUN_80022264(1,6);
          uStack_84 = uStack_84 ^ 0x80000000;
          local_88 = 0x43300000;
          local_380 = FLOAT_803e13bc *
                      (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e13d8);
          uStack_8c = FUN_80022264(1,6);
          uStack_8c = uStack_8c ^ 0x80000000;
          local_90 = 0x43300000;
          local_37c = FLOAT_803e13bc *
                      (float)((double)CONCAT44(0x43300000,uStack_8c) - DOUBLE_803e13d8);
          uStack_94 = FUN_80022264(1,6);
          uStack_94 = uStack_94 ^ 0x80000000;
          local_98 = 0x43300000;
          local_378 = FLOAT_803e13bc *
                      (float)((double)CONCAT44(0x43300000,uStack_94) - DOUBLE_803e13d8);
          puVar9 = &local_36c;
        }
        *(undefined *)((int)puVar9 + 0x16) = 1;
        *(undefined2 *)(puVar9 + 5) = 0;
        puVar9[4] = 0;
        *puVar9 = 0x80000000;
        puVar9[1] = (float)dVar10;
        puVar9[2] = (float)dVar11;
        puVar9[3] = (float)dVar10;
        *(undefined *)((int)puVar9 + 0x2e) = 1;
        *(undefined2 *)(puVar9 + 0xb) = 0;
        puVar9[10] = 0;
        puVar9[6] = 0x100;
        puVar9[7] = (float)dVar10;
        uStack_84 = FUN_80022264(0xfffffff6,10);
        uStack_84 = uStack_84 ^ 0x80000000;
        local_88 = 0x43300000;
        puVar9[8] = (float)(dVar13 * (double)(float)((double)CONCAT44(0x43300000,uStack_84) - dVar12
                                                    ));
        uStack_8c = FUN_80022264(0xfffffff6,10);
        uStack_8c = uStack_8c ^ 0x80000000;
        local_90 = 0x43300000;
        puVar9[9] = (float)(dVar13 * (double)(float)((double)CONCAT44(0x43300000,uStack_8c) - dVar12
                                                    ));
        if (uVar6 == 0x10) {
          *(undefined *)((int)puVar9 + 0x46) = 1;
          *(undefined2 *)(puVar9 + 0x11) = 0;
          puVar9[0x10] = 0;
          puVar9[0xc] = 0x400000;
          puVar9[0xd] = FLOAT_803e13b4;
          puVar9[0xe] = FLOAT_803e13b4;
          uStack_84 = FUN_80022264(0,300);
          uStack_84 = uStack_84 ^ 0x80000000;
          local_88 = 0x43300000;
          puVar9[0xf] = FLOAT_803e13d0 +
                        (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e13d8);
          uVar5 = FUN_80022264(0xffff8001,0xfffff060);
          local_412 = (undefined2)uVar5;
          uVar5 = FUN_80022264(0,0xffff);
          local_414 = (ushort)uVar5;
          FUN_80021b8c(&local_414,(float *)(puVar9 + 0xd));
        }
        else if (uVar6 == 0x11) {
          *(undefined *)((int)puVar9 + 0x46) = 1;
          *(undefined2 *)(puVar9 + 0x11) = 0;
          puVar9[0x10] = 0;
          puVar9[0xc] = 0x400000;
          puVar9[0xd] = FLOAT_803e13b4;
          puVar9[0xe] = FLOAT_803e13b4;
          uStack_84 = FUN_80022264(0,300);
          uStack_84 = uStack_84 ^ 0x80000000;
          local_88 = 0x43300000;
          puVar9[0xf] = FLOAT_803e13d0 +
                        (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e13d8);
          uVar5 = FUN_80022264(0xffff8001,0xfffff060);
          local_412 = (undefined2)uVar5;
          uVar5 = FUN_80022264(0,0xffff);
          local_414 = (ushort)uVar5;
          FUN_80021b8c(&local_414,(float *)(puVar9 + 0xd));
        }
        else {
          *(undefined *)((int)puVar9 + 0x46) = 1;
          *(undefined2 *)(puVar9 + 0x11) = 0;
          puVar9[0x10] = 0;
          puVar9[0xc] = 0x400000;
          puVar9[0xd] = FLOAT_803e13b4;
          puVar9[0xe] = FLOAT_803e13b4;
          uStack_84 = FUN_80022264(0,100);
          uStack_84 = uStack_84 ^ 0x80000000;
          local_88 = 0x43300000;
          puVar9[0xf] = FLOAT_803e13d4 +
                        (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e13d8);
          uVar5 = FUN_80022264(0xffff8001,0xfffff060);
          local_412 = (undefined2)uVar5;
          uVar5 = FUN_80022264(0,0xffff);
          local_414 = (ushort)uVar5;
          FUN_80021b8c(&local_414,(float *)(puVar9 + 0xd));
        }
        *(undefined *)((int)puVar9 + 0x5e) = 1;
        *(undefined2 *)(puVar9 + 0x17) = 4;
        puVar9[0x16] = &DAT_803dc514;
        puVar9[0x12] = 4;
        puVar9[0x13] = (float)dVar10;
        puVar9[0x14] = (float)dVar10;
        puVar9[0x15] = (float)dVar10;
        iVar1 = (int)puVar9 + (0x60 - (int)&local_39c);
        iVar1 = iVar1 / 0x18 + (iVar1 >> 0x1f);
        local_39f = (char)iVar1 - (char)(iVar1 >> 0x1f);
        local_3fc = &local_39c;
        local_3a8 = param_12 | 0x4000000;
        (**(code **)(*DAT_803dd6fc + 8))(&local_3fc,0,4,&DAT_80312a80,4,&DAT_80312aa8,0,uVar4);
      }
      uVar3 = FUN_80022264(2,6);
      if (uVar6 == 7) {
        uVar6 = FUN_80022264(4,6);
      }
      if (uVar6 == 0xb) {
        uVar6 = FUN_80022264(8,10);
      }
      if (uVar6 == 0xc) {
        uVar3 = FUN_80022264(1,3);
      }
      switch(uVar6) {
      case 0:
      case 0x14:
        local_410 = 0x2a;
        for (; uVar3 != 0; uVar3 = uVar3 - 1) {
          (**(code **)(*DAT_803dd708 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
        }
        break;
      case 1:
        local_410 = 0x2b;
        (**(code **)(*DAT_803dd708 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
        (**(code **)(*DAT_803dd708 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
        break;
      case 2:
        local_410 = 0x184;
        for (; uVar3 != 0; uVar3 = uVar3 - 1) {
          (**(code **)(*DAT_803dd708 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
        }
        break;
      case 3:
        local_410 = 0x1a1;
        for (; uVar3 != 0; uVar3 = uVar3 - 1) {
          (**(code **)(*DAT_803dd708 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
        }
        break;
      case 4:
        local_410 = 0x60;
        for (; uVar3 != 0; uVar3 = uVar3 - 1) {
          (**(code **)(*DAT_803dd708 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
        }
        local_410 = 0x159;
        (**(code **)(*DAT_803dd708 + 8))(iVar2,3,&local_414,1,0xffffffff,0);
        break;
      case 5:
        local_410 = 0x60;
        for (; uVar3 != 0; uVar3 = uVar3 - 1) {
          (**(code **)(*DAT_803dd708 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
        }
        local_410 = 0x91;
        (**(code **)(*DAT_803dd708 + 8))(iVar2,3,&local_414,1,0xffffffff,0);
        break;
      case 6:
        local_410 = 0x60;
        for (; uVar3 != 0; uVar3 = uVar3 - 1) {
          (**(code **)(*DAT_803dd708 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
        }
        local_410 = 0x74;
        (**(code **)(*DAT_803dd708 + 8))(iVar2,3,&local_414,1,0xffffffff,0);
        break;
      default:
        local_410 = 0x2a;
        iVar8 = 5;
        do {
          (**(code **)(*DAT_803dd708 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
          iVar8 = iVar8 + -1;
        } while (iVar8 != 0);
        break;
      case 8:
        local_410 = 0x60;
        for (; uVar3 != 0; uVar3 = uVar3 - 1) {
          (**(code **)(*DAT_803dd708 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
        }
        iVar8 = 0x14;
        local_410 = 0xdf;
        do {
          (**(code **)(*DAT_803dd708 + 8))(iVar2,7,&local_414,1,0xffffffff,0);
          iVar8 = iVar8 + -1;
        } while (iVar8 != 0);
        local_410 = 0x159;
        (**(code **)(*DAT_803dd708 + 8))(iVar2,3,&local_414,1,0xffffffff,0);
        break;
      case 9:
        local_410 = 0x60;
        for (; uVar3 != 0; uVar3 = uVar3 - 1) {
          (**(code **)(*DAT_803dd708 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
        }
        iVar8 = 0x14;
        local_410 = 0xde;
        do {
          (**(code **)(*DAT_803dd708 + 8))(iVar2,7,&local_414,1,0xffffffff,0);
          iVar8 = iVar8 + -1;
        } while (iVar8 != 0);
        local_410 = 0x91;
        (**(code **)(*DAT_803dd708 + 8))(iVar2,3,&local_414,1,0xffffffff,0);
        break;
      case 10:
        local_410 = 0x60;
        for (; uVar3 != 0; uVar3 = uVar3 - 1) {
          (**(code **)(*DAT_803dd708 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
        }
        iVar8 = 0x14;
        local_410 = 0x160;
        do {
          (**(code **)(*DAT_803dd708 + 8))(iVar2,7,&local_414,1,0xffffffff,0);
          iVar8 = iVar8 + -1;
        } while (iVar8 != 0);
        local_410 = 0x74;
        (**(code **)(*DAT_803dd708 + 8))(iVar2,3,&local_414,1,0xffffffff,0);
        break;
      case 0xc:
        local_410 = 0x2a;
        break;
      case 0xd:
        local_410 = 0x4c;
        (**(code **)(*DAT_803dd708 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
        (**(code **)(*DAT_803dd708 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
        break;
      case 0xe:
        local_410 = 0x60;
        for (; uVar3 != 0; uVar3 = uVar3 - 1) {
          (**(code **)(*DAT_803dd708 + 8))(iVar2,0x135,&local_414,1,0xffffffff,0);
        }
        break;
      case 0xf:
        (**(code **)(*DAT_803dd708 + 8))(iVar2,0x51b,0,2,0xffffffff,0);
        (**(code **)(*DAT_803dd708 + 8))(iVar2,0x51b,0,2,0xffffffff,0);
        (**(code **)(*DAT_803dd708 + 8))(iVar2,0x51b,0,2,0xffffffff,0);
        (**(code **)(*DAT_803dd708 + 8))(iVar2,0x51b,0,2,0xffffffff,0);
        break;
      case 0x10:
      case 0x11:
        local_410 = 0x4c;
        (**(code **)(*DAT_803dd708 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
        (**(code **)(*DAT_803dd708 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
      }
    }
  }
  FUN_8028686c();
  return;
}

