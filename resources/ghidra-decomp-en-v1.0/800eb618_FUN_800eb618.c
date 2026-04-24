// Function: FUN_800eb618
// Entry: 800eb618
// Size: 4516 bytes

/* WARNING: Removing unreachable block (ram,0x800ec794) */
/* WARNING: Removing unreachable block (ram,0x800ec784) */
/* WARNING: Removing unreachable block (ram,0x800ec78c) */
/* WARNING: Removing unreachable block (ram,0x800ec79c) */
/* WARNING: Could not reconcile some variable overlaps */

void FUN_800eb618(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint in_r6;
  undefined4 *in_r8;
  int iVar5;
  undefined4 uVar6;
  undefined4 *puVar7;
  undefined4 uVar8;
  undefined8 in_f28;
  double dVar9;
  undefined8 in_f29;
  double dVar10;
  undefined8 in_f30;
  double dVar11;
  undefined8 in_f31;
  double dVar12;
  undefined8 uVar13;
  undefined4 local_418;
  undefined2 local_414;
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
  uint uStack148;
  undefined4 local_90;
  uint uStack140;
  undefined4 local_88;
  uint uStack132;
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar8 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  uVar13 = FUN_802860bc();
  iVar2 = (int)((ulonglong)uVar13 >> 0x20);
  iVar4 = (int)uVar13;
  uVar6 = 0;
  local_418 = DAT_803e0730;
  if (in_r8 != (undefined4 *)0x0) {
    local_418 = *in_r8;
  }
  if (iVar2 == 0) {
    FUN_801378a8(s______This_modgfx_needs_an_owner_o_80311ea0);
    uVar6 = 0xffffffff;
  }
  else {
    local_408 = FLOAT_803e0734;
    local_404 = FLOAT_803e0734;
    local_400 = FLOAT_803e0734;
    local_40c = FLOAT_803e0738;
    local_410 = 0;
    iVar5 = **(int **)(*(int *)(iVar2 + 0x7c) + *(char *)(iVar2 + 0xad) * 4);
    if (*(char *)(iVar5 + 0xf2) == '\0') {
      uVar6 = 0xffffffff;
    }
    else {
      local_3a4 = (undefined)uVar13;
      local_3b8 = (undefined2)uVar13;
      local_3d0 = FLOAT_803e0734;
      local_3cc = FLOAT_803e0734;
      local_3c8 = FLOAT_803e0734;
      local_3dc = FLOAT_803e0734;
      local_3d8 = FLOAT_803e0734;
      local_3d4 = FLOAT_803e0734;
      local_3c4 = FLOAT_803e0738;
      local_3bc = 1;
      local_3c0 = 0;
      local_3a3 = 4;
      local_3a2 = 0;
      local_3a1 = 0;
      local_3b6 = DAT_80311e70;
      local_3b4 = DAT_80311e72;
      local_3b2 = DAT_80311e74;
      local_3b0 = DAT_80311e76;
      local_3ae = DAT_80311e78;
      local_3ac = DAT_80311e7a;
      local_3aa = DAT_80311e7c;
      local_3f8 = iVar2;
      iVar3 = FUN_800221a0((int)local_418._0_2_,(int)local_418._2_2_);
      if (iVar4 == 0xc) {
        iVar3 = FUN_800221a0(2,6);
      }
      else if (iVar4 == 0xd) {
        iVar3 = FUN_800221a0(2,6);
      }
      else if (iVar4 == 0x11) {
        iVar3 = 5;
      }
      dVar9 = (double)FLOAT_803e0734;
      dVar10 = (double)FLOAT_803e074c;
      dVar12 = (double)FLOAT_803e0750;
      dVar11 = DOUBLE_803e0758;
      for (; iVar3 != 0; iVar3 = iVar3 + -1) {
        uVar6 = FUN_800536c0(**(undefined4 **)(iVar5 + 0x20));
        local_386 = 0;
        local_388 = 1;
        local_38c = &DAT_803db8b0;
        local_39c = 8;
        local_398 = (float)dVar9;
        local_394 = (float)dVar9;
        local_390 = (float)dVar9;
        if ((iVar4 == 0xc) || (iVar4 == 5)) {
          local_36e = 0;
          local_370 = 4;
          local_374 = &DAT_803db8b4;
          local_384 = 2;
          uStack148 = FUN_800221a0(1,6);
          uStack148 = uStack148 ^ 0x80000000;
          local_98 = 0x43300000;
          local_380 = FLOAT_803e073c *
                      (float)((double)CONCAT44(0x43300000,uStack148) - DOUBLE_803e0758);
          uStack140 = FUN_800221a0(1,6);
          uStack140 = uStack140 ^ 0x80000000;
          local_90 = 0x43300000;
          local_37c = FLOAT_803e073c *
                      (float)((double)CONCAT44(0x43300000,uStack140) - DOUBLE_803e0758);
          uStack132 = FUN_800221a0(1,6);
          uStack132 = uStack132 ^ 0x80000000;
          local_88 = 0x43300000;
          local_378 = FLOAT_803e073c *
                      (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803e0758);
          puVar7 = &local_36c;
        }
        else if (iVar4 == 0xd) {
          local_36e = 0;
          local_370 = 4;
          local_374 = &DAT_803db8b4;
          local_384 = 2;
          uStack132 = FUN_800221a0(1,6);
          uStack132 = uStack132 ^ 0x80000000;
          local_88 = 0x43300000;
          local_380 = FLOAT_803e073c *
                      (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803e0758);
          uStack140 = FUN_800221a0(1,6);
          uStack140 = uStack140 ^ 0x80000000;
          local_90 = 0x43300000;
          local_37c = FLOAT_803e073c *
                      (float)((double)CONCAT44(0x43300000,uStack140) - DOUBLE_803e0758);
          uStack148 = FUN_800221a0(1,6);
          uStack148 = uStack148 ^ 0x80000000;
          local_98 = 0x43300000;
          local_378 = FLOAT_803e073c *
                      (float)((double)CONCAT44(0x43300000,uStack148) - DOUBLE_803e0758);
          puVar7 = &local_36c;
        }
        else if (iVar4 == 0x14) {
          local_36e = 0;
          local_370 = 4;
          local_374 = &DAT_803db8b4;
          local_384 = 2;
          uStack132 = FUN_800221a0(3,6);
          uStack132 = uStack132 ^ 0x80000000;
          local_88 = 0x43300000;
          local_380 = FLOAT_803e0740 *
                      (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803e0758);
          uStack140 = FUN_800221a0(3,6);
          uStack140 = uStack140 ^ 0x80000000;
          local_90 = 0x43300000;
          local_37c = FLOAT_803e0740 *
                      (float)((double)CONCAT44(0x43300000,uStack140) - DOUBLE_803e0758);
          uStack148 = FUN_800221a0(3,6);
          uStack148 = uStack148 ^ 0x80000000;
          local_98 = 0x43300000;
          local_378 = FLOAT_803e0740 *
                      (float)((double)CONCAT44(0x43300000,uStack148) - DOUBLE_803e0758);
          puVar7 = &local_36c;
        }
        else if (iVar4 == 0x11) {
          local_36e = 0;
          local_370 = 4;
          local_374 = &DAT_803db8b4;
          local_384 = 2;
          uStack132 = FUN_800221a0(3,6);
          uStack132 = uStack132 ^ 0x80000000;
          local_88 = 0x43300000;
          local_380 = FLOAT_803e0740 *
                      (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803e0758);
          uStack140 = FUN_800221a0(3,6);
          uStack140 = uStack140 ^ 0x80000000;
          local_90 = 0x43300000;
          local_37c = FLOAT_803e0740 *
                      (float)((double)CONCAT44(0x43300000,uStack140) - DOUBLE_803e0758);
          uStack148 = FUN_800221a0(3,6);
          uStack148 = uStack148 ^ 0x80000000;
          local_98 = 0x43300000;
          local_378 = FLOAT_803e0740 *
                      (float)((double)CONCAT44(0x43300000,uStack148) - DOUBLE_803e0758);
          puVar7 = &local_36c;
        }
        else if (iVar4 == 0x10) {
          local_36e = 0;
          local_370 = 4;
          local_374 = &DAT_803db8b4;
          local_384 = 8;
          local_380 = FLOAT_803e0744;
          local_37c = (float)dVar9;
          local_378 = FLOAT_803e0744;
          local_356[0] = 0;
          local_358 = 4;
          local_35c = &DAT_803db8b4;
          local_36c = 2;
          uStack132 = FUN_800221a0(3,6);
          uStack132 = uStack132 ^ 0x80000000;
          local_88 = 0x43300000;
          local_368 = FLOAT_803e0748 *
                      (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803e0758);
          uStack140 = FUN_800221a0(3,6);
          uStack140 = uStack140 ^ 0x80000000;
          local_90 = 0x43300000;
          local_364 = FLOAT_803e0748 *
                      (float)((double)CONCAT44(0x43300000,uStack140) - DOUBLE_803e0758);
          uStack148 = FUN_800221a0(3,6);
          uStack148 = uStack148 ^ 0x80000000;
          local_98 = 0x43300000;
          local_360 = FLOAT_803e0748 *
                      (float)((double)CONCAT44(0x43300000,uStack148) - DOUBLE_803e0758);
          puVar7 = (undefined4 *)(local_356 + 2);
        }
        else {
          local_36e = 0;
          local_370 = 4;
          local_374 = &DAT_803db8b4;
          local_384 = 2;
          uStack132 = FUN_800221a0(1,6);
          uStack132 = uStack132 ^ 0x80000000;
          local_88 = 0x43300000;
          local_380 = FLOAT_803e073c *
                      (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803e0758);
          uStack140 = FUN_800221a0(1,6);
          uStack140 = uStack140 ^ 0x80000000;
          local_90 = 0x43300000;
          local_37c = FLOAT_803e073c *
                      (float)((double)CONCAT44(0x43300000,uStack140) - DOUBLE_803e0758);
          uStack148 = FUN_800221a0(1,6);
          uStack148 = uStack148 ^ 0x80000000;
          local_98 = 0x43300000;
          local_378 = FLOAT_803e073c *
                      (float)((double)CONCAT44(0x43300000,uStack148) - DOUBLE_803e0758);
          puVar7 = &local_36c;
        }
        *(undefined *)((int)puVar7 + 0x16) = 1;
        *(undefined2 *)(puVar7 + 5) = 0;
        puVar7[4] = 0;
        *puVar7 = 0x80000000;
        puVar7[1] = (float)dVar9;
        puVar7[2] = (float)dVar10;
        puVar7[3] = (float)dVar9;
        *(undefined *)((int)puVar7 + 0x2e) = 1;
        *(undefined2 *)(puVar7 + 0xb) = 0;
        puVar7[10] = 0;
        puVar7[6] = 0x100;
        puVar7[7] = (float)dVar9;
        uStack132 = FUN_800221a0(0xfffffff6,10);
        uStack132 = uStack132 ^ 0x80000000;
        local_88 = 0x43300000;
        puVar7[8] = (float)(dVar12 * (double)(float)((double)CONCAT44(0x43300000,uStack132) - dVar11
                                                    ));
        uStack140 = FUN_800221a0(0xfffffff6,10);
        uStack140 = uStack140 ^ 0x80000000;
        local_90 = 0x43300000;
        puVar7[9] = (float)(dVar12 * (double)(float)((double)CONCAT44(0x43300000,uStack140) - dVar11
                                                    ));
        if (iVar4 == 0x10) {
          *(undefined *)((int)puVar7 + 0x46) = 1;
          *(undefined2 *)(puVar7 + 0x11) = 0;
          puVar7[0x10] = 0;
          puVar7[0xc] = 0x400000;
          puVar7[0xd] = FLOAT_803e0734;
          puVar7[0xe] = FLOAT_803e0734;
          uStack132 = FUN_800221a0(0,300);
          uStack132 = uStack132 ^ 0x80000000;
          local_88 = 0x43300000;
          puVar7[0xf] = FLOAT_803e0750 +
                        (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803e0758);
          local_412 = FUN_800221a0(0xffff8001,0xfffff060);
          local_414 = FUN_800221a0(0,0xffff);
          FUN_80021ac8(&local_414,puVar7 + 0xd);
        }
        else if (iVar4 == 0x11) {
          *(undefined *)((int)puVar7 + 0x46) = 1;
          *(undefined2 *)(puVar7 + 0x11) = 0;
          puVar7[0x10] = 0;
          puVar7[0xc] = 0x400000;
          puVar7[0xd] = FLOAT_803e0734;
          puVar7[0xe] = FLOAT_803e0734;
          uStack132 = FUN_800221a0(0,300);
          uStack132 = uStack132 ^ 0x80000000;
          local_88 = 0x43300000;
          puVar7[0xf] = FLOAT_803e0750 +
                        (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803e0758);
          local_412 = FUN_800221a0(0xffff8001,0xfffff060);
          local_414 = FUN_800221a0(0,0xffff);
          FUN_80021ac8(&local_414,puVar7 + 0xd);
        }
        else {
          *(undefined *)((int)puVar7 + 0x46) = 1;
          *(undefined2 *)(puVar7 + 0x11) = 0;
          puVar7[0x10] = 0;
          puVar7[0xc] = 0x400000;
          puVar7[0xd] = FLOAT_803e0734;
          puVar7[0xe] = FLOAT_803e0734;
          uStack132 = FUN_800221a0(0,100);
          uStack132 = uStack132 ^ 0x80000000;
          local_88 = 0x43300000;
          puVar7[0xf] = FLOAT_803e0754 +
                        (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803e0758);
          local_412 = FUN_800221a0(0xffff8001,0xfffff060);
          local_414 = FUN_800221a0(0,0xffff);
          FUN_80021ac8(&local_414,puVar7 + 0xd);
        }
        *(undefined *)((int)puVar7 + 0x5e) = 1;
        *(undefined2 *)(puVar7 + 0x17) = 4;
        puVar7[0x16] = &DAT_803db8b4;
        puVar7[0x12] = 4;
        puVar7[0x13] = (float)dVar9;
        puVar7[0x14] = (float)dVar9;
        puVar7[0x15] = (float)dVar9;
        iVar1 = (int)puVar7 + (0x60 - (int)&local_39c);
        iVar1 = iVar1 / 0x18 + (iVar1 >> 0x1f);
        local_39f = (char)iVar1 - (char)(iVar1 >> 0x1f);
        local_3fc = &local_39c;
        local_3a8 = in_r6 | 0x4000000;
        uVar6 = (**(code **)(*DAT_803dca7c + 8))
                          (&local_3fc,0,4,&DAT_80311e30,4,&DAT_80311e58,0,uVar6);
      }
      iVar5 = FUN_800221a0(2,6);
      if (iVar4 == 7) {
        iVar4 = FUN_800221a0(4,6);
      }
      if (iVar4 == 0xb) {
        iVar4 = FUN_800221a0(8,10);
      }
      if (iVar4 == 0xc) {
        iVar5 = FUN_800221a0(1,3);
      }
      switch(iVar4) {
      case 0:
      case 0x14:
        local_410 = 0x2a;
        for (; iVar5 != 0; iVar5 = iVar5 + -1) {
          (**(code **)(*DAT_803dca88 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
        }
        break;
      case 1:
        local_410 = 0x2b;
        (**(code **)(*DAT_803dca88 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
        (**(code **)(*DAT_803dca88 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
        break;
      case 2:
        local_410 = 0x184;
        for (; iVar5 != 0; iVar5 = iVar5 + -1) {
          (**(code **)(*DAT_803dca88 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
        }
        break;
      case 3:
        local_410 = 0x1a1;
        for (; iVar5 != 0; iVar5 = iVar5 + -1) {
          (**(code **)(*DAT_803dca88 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
        }
        break;
      case 4:
        local_410 = 0x60;
        for (; iVar5 != 0; iVar5 = iVar5 + -1) {
          (**(code **)(*DAT_803dca88 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
        }
        local_410 = 0x159;
        (**(code **)(*DAT_803dca88 + 8))(iVar2,3,&local_414,1,0xffffffff,0);
        break;
      case 5:
        local_410 = 0x60;
        for (; iVar5 != 0; iVar5 = iVar5 + -1) {
          (**(code **)(*DAT_803dca88 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
        }
        local_410 = 0x91;
        (**(code **)(*DAT_803dca88 + 8))(iVar2,3,&local_414,1,0xffffffff,0);
        break;
      case 6:
        local_410 = 0x60;
        for (; iVar5 != 0; iVar5 = iVar5 + -1) {
          (**(code **)(*DAT_803dca88 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
        }
        local_410 = 0x74;
        (**(code **)(*DAT_803dca88 + 8))(iVar2,3,&local_414,1,0xffffffff,0);
        break;
      default:
        local_410 = 0x2a;
        iVar4 = 5;
        do {
          (**(code **)(*DAT_803dca88 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
          iVar4 = iVar4 + -1;
        } while (iVar4 != 0);
        break;
      case 8:
        local_410 = 0x60;
        for (; iVar5 != 0; iVar5 = iVar5 + -1) {
          (**(code **)(*DAT_803dca88 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
        }
        iVar4 = 0x14;
        local_410 = 0xdf;
        do {
          (**(code **)(*DAT_803dca88 + 8))(iVar2,7,&local_414,1,0xffffffff,0);
          iVar4 = iVar4 + -1;
        } while (iVar4 != 0);
        local_410 = 0x159;
        (**(code **)(*DAT_803dca88 + 8))(iVar2,3,&local_414,1,0xffffffff,0);
        break;
      case 9:
        local_410 = 0x60;
        for (; iVar5 != 0; iVar5 = iVar5 + -1) {
          (**(code **)(*DAT_803dca88 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
        }
        iVar4 = 0x14;
        local_410 = 0xde;
        do {
          (**(code **)(*DAT_803dca88 + 8))(iVar2,7,&local_414,1,0xffffffff,0);
          iVar4 = iVar4 + -1;
        } while (iVar4 != 0);
        local_410 = 0x91;
        (**(code **)(*DAT_803dca88 + 8))(iVar2,3,&local_414,1,0xffffffff,0);
        break;
      case 10:
        local_410 = 0x60;
        for (; iVar5 != 0; iVar5 = iVar5 + -1) {
          (**(code **)(*DAT_803dca88 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
        }
        iVar4 = 0x14;
        local_410 = 0x160;
        do {
          (**(code **)(*DAT_803dca88 + 8))(iVar2,7,&local_414,1,0xffffffff,0);
          iVar4 = iVar4 + -1;
        } while (iVar4 != 0);
        local_410 = 0x74;
        (**(code **)(*DAT_803dca88 + 8))(iVar2,3,&local_414,1,0xffffffff,0);
        break;
      case 0xc:
        local_410 = 0x2a;
        break;
      case 0xd:
        local_410 = 0x4c;
        (**(code **)(*DAT_803dca88 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
        (**(code **)(*DAT_803dca88 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
        break;
      case 0xe:
        local_410 = 0x60;
        for (; iVar5 != 0; iVar5 = iVar5 + -1) {
          (**(code **)(*DAT_803dca88 + 8))(iVar2,0x135,&local_414,1,0xffffffff,0);
        }
        break;
      case 0xf:
        (**(code **)(*DAT_803dca88 + 8))(iVar2,0x51b,0,2,0xffffffff,0);
        (**(code **)(*DAT_803dca88 + 8))(iVar2,0x51b,0,2,0xffffffff,0);
        (**(code **)(*DAT_803dca88 + 8))(iVar2,0x51b,0,2,0xffffffff,0);
        (**(code **)(*DAT_803dca88 + 8))(iVar2,0x51b,0,2,0xffffffff,0);
        break;
      case 0x10:
      case 0x11:
        local_410 = 0x4c;
        (**(code **)(*DAT_803dca88 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
        (**(code **)(*DAT_803dca88 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
      }
    }
  }
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  __psq_l0(auStack24,uVar8);
  __psq_l1(auStack24,uVar8);
  __psq_l0(auStack40,uVar8);
  __psq_l1(auStack40,uVar8);
  __psq_l0(auStack56,uVar8);
  __psq_l1(auStack56,uVar8);
  FUN_80286108(uVar6);
  return;
}

