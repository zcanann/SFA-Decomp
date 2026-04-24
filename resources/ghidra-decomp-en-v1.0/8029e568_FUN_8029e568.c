// Function: FUN_8029e568
// Entry: 8029e568
// Size: 1636 bytes

/* WARNING: Removing unreachable block (ram,0x8029eba4) */

undefined4 FUN_8029e568(undefined8 param_1,int param_2,uint *param_3)

{
  float fVar1;
  short sVar2;
  bool bVar3;
  float fVar4;
  float fVar5;
  undefined2 uVar8;
  int iVar6;
  undefined4 uVar7;
  int iVar9;
  int iVar10;
  undefined4 uVar11;
  double dVar12;
  undefined8 in_f31;
  uint local_38;
  undefined4 local_34;
  undefined auStack48 [16];
  undefined auStack8 [8];
  
  uVar11 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar10 = *(int *)(param_2 + 0xb8);
  local_38 = 0;
  if (*(char *)((int)param_3 + 0x27a) != '\0') {
    *(undefined2 *)(param_3 + 0x9e) = 0x1b;
    *(code **)(iVar10 + 0x898) = FUN_802a00c0;
    FUN_80035e8c();
  }
  iVar9 = *(int *)(param_2 + 0xb8);
  *(uint *)(iVar9 + 0x360) = *(uint *)(iVar9 + 0x360) & 0xfffffffd;
  *(uint *)(iVar9 + 0x360) = *(uint *)(iVar9 + 0x360) | 0x2000;
  param_3[1] = param_3[1] | 0x100000;
  fVar1 = FLOAT_803e7ea4;
  param_3[0xa0] = (uint)FLOAT_803e7ea4;
  param_3[0xa1] = (uint)fVar1;
  *param_3 = *param_3 | 0x200000;
  *(float *)(param_2 + 0x24) = fVar1;
  *(float *)(param_2 + 0x2c) = fVar1;
  *(undefined *)((int)param_3 + 0x25f) = 0;
  *(float *)(param_2 + 0x28) = fVar1;
  sVar2 = *(short *)(param_2 + 0xa0);
  if (sVar2 == 0x40d) {
LAB_8029e650:
    fVar1 = (float)param_3[0xa3];
    fVar4 = fVar1 / FLOAT_803e7fa8;
    if (fVar4 < FLOAT_803e7ea4) {
      fVar4 = -fVar4;
    }
    fVar5 = FLOAT_803e7efc;
    if ((FLOAT_803e7efc <= fVar4) && (fVar5 = fVar4, FLOAT_803e7ee0 < fVar4)) {
      fVar5 = FLOAT_803e7ee0;
    }
    if (fVar1 <= FLOAT_803e7ee0) {
      if (FLOAT_803e7ecc <= fVar1) {
        dVar12 = (double)FLOAT_803e7ea4;
        bVar3 = false;
      }
      else {
        dVar12 = (double)(FLOAT_803e7f44 * -fVar5);
        bVar3 = true;
      }
    }
    else {
      dVar12 = (double)(FLOAT_803e7f44 * fVar5);
      bVar3 = true;
    }
    if ((bVar3) && (DAT_803de480 = DAT_803de480 - (uint)DAT_803db410, DAT_803de480 < 1)) {
      DAT_803de480 = FUN_800221a0(0x1e,0x2d);
      FUN_8000bb18(0,0x378);
    }
    dVar12 = (double)FUN_80021370((double)(float)(dVar12 - (double)(float)param_3[0xa5]),
                                  (double)FLOAT_803e7efc,(double)FLOAT_803db414);
    param_3[0xa5] = (uint)(float)((double)(float)param_3[0xa5] + dVar12);
    *(float *)(iVar10 + 0x640) = (float)param_3[0xa5] * FLOAT_803db414 + *(float *)(iVar10 + 0x640);
    if ((FLOAT_803e7ef8 <= (float)param_3[0xa5]) || ((float)param_3[0xa5] <= FLOAT_803e7fec)) {
      if (*(short *)(param_2 + 0xa0) != 0x40d) {
        FUN_80030334((double)FLOAT_803e7ea4,param_2,0x40d,0);
      }
      FUN_8002f5d4((double)(float)param_3[0xa5],param_2,param_3 + 0xa8);
    }
    else {
      param_3[0xa5] = (uint)FLOAT_803e7ea4;
      if (*(short *)(param_2 + 0xa0) != 0x76) {
        FUN_80030334(param_2,0x76,0);
      }
      param_3[0xa8] = (uint)FLOAT_803e7f78;
    }
    bVar3 = false;
    if ((*(float *)(iVar10 + 0x644) < *(float *)(iVar10 + 0x640)) ||
       (*(float *)(iVar10 + 0x640) < FLOAT_803e7ea4)) {
      bVar3 = true;
    }
    if (bVar3) {
      FUN_80030334((double)FLOAT_803e7ea4,param_2,0x40f,0);
      if ((*(char *)(iVar10 + 0x8c8) != 'H') && (*(char *)(iVar10 + 0x8c8) != 'G')) {
        local_38 = (uint)(FLOAT_803e7ea4 <= *(float *)(iVar10 + 0x640));
        (**(code **)(*DAT_803dca50 + 0x60))(&local_38);
      }
    }
    else {
      uVar8 = FUN_800217c0(-(double)*(float *)(iVar10 + 0x634),-(double)*(float *)(iVar10 + 0x63c));
      *(undefined2 *)(iVar10 + 0x478) = uVar8;
      *(undefined2 *)(iVar10 + 0x484) = *(undefined2 *)(iVar10 + 0x478);
      *(undefined2 *)(param_2 + 2) = 0;
    }
  }
  else if (sVar2 < 0x40d) {
    if (sVar2 == 0x76) goto LAB_8029e650;
LAB_8029e9b4:
    local_34 = 0x1f;
    iVar9 = (**(code **)(*DAT_803dca9c + 0x14))
                      ((double)*(float *)(param_2 + 0xc),(double)*(float *)(param_2 + 0x10),
                       (double)*(float *)(param_2 + 0x14),&local_34,1,0);
    if (iVar9 != -1) {
      iVar9 = (**(code **)(*DAT_803dca9c + 0x1c))();
      *(undefined4 *)(iVar10 + 0x61c) = *(undefined4 *)(iVar9 + 8);
      *(undefined4 *)(iVar10 + 0x620) = *(undefined4 *)(iVar9 + 0xc);
      *(undefined4 *)(iVar10 + 0x624) = *(undefined4 *)(iVar9 + 0x10);
      *(undefined4 *)(param_2 + 0xc) = *(undefined4 *)(iVar9 + 8);
      *(undefined4 *)(param_2 + 0x10) = *(undefined4 *)(iVar9 + 0xc);
      *(undefined4 *)(param_2 + 0x14) = *(undefined4 *)(iVar9 + 0x10);
      uVar8 = FUN_800217c0((double)*(float *)(iVar10 + 0x60c),(double)*(float *)(iVar10 + 0x614));
      *(undefined2 *)(iVar10 + 0x478) = uVar8;
      *(undefined2 *)(iVar10 + 0x484) = *(undefined2 *)(iVar10 + 0x478);
      FUN_802931a0((double)(*(float *)(iVar10 + 0x60c) * *(float *)(iVar10 + 0x60c) +
                           *(float *)(iVar10 + 0x614) * *(float *)(iVar10 + 0x614)));
      *(undefined2 *)(param_2 + 2) = 0;
      iVar6 = (**(code **)(*DAT_803dca9c + 0x54))(iVar9,0xffffffff);
      if (iVar6 == -1) {
        (**(code **)(*DAT_803dca9c + 0x60))(iVar9,0xffffffff);
      }
      iVar9 = (**(code **)(*DAT_803dca9c + 0x1c))();
      *(undefined4 *)(iVar10 + 0x628) = *(undefined4 *)(iVar9 + 8);
      *(undefined4 *)(iVar10 + 0x62c) = *(undefined4 *)(iVar9 + 0xc);
      *(undefined4 *)(iVar10 + 0x630) = *(undefined4 *)(iVar9 + 0x10);
      *(float *)(iVar10 + 0x640) = FLOAT_803e7ea4;
      FUN_80247754(iVar10 + 0x628,iVar10 + 0x61c,auStack48);
      dVar12 = (double)FUN_802477f0(auStack48);
      *(float *)(iVar10 + 0x644) = (float)dVar12;
      FUN_80247794(auStack48,iVar10 + 0x634);
    }
    FUN_80030334((double)FLOAT_803e7ea4,param_2,0x40e,0);
    if ((*(char *)(iVar10 + 0x8c8) != 'H') && (*(char *)(iVar10 + 0x8c8) != 'G')) {
      (**(code **)(*DAT_803dca50 + 0x1c))(0x50,1,0,0,0,0x28,0xff);
    }
    param_3[0xa5] = (uint)FLOAT_803e7ea4;
  }
  else if (sVar2 == 0x40f) {
    param_3[0xa8] = (uint)FLOAT_803e7f34;
    (**(code **)(*DAT_803dca8c + 0x20))(param_1,param_2,param_3,1);
    if (*(char *)((int)param_3 + 0x346) != '\0') {
      if ((*(char *)(iVar10 + 0x8c8) != 'H') && (*(char *)(iVar10 + 0x8c8) != 'G')) {
        (**(code **)(*DAT_803dca50 + 0x1c))(0x42,1,1,0,0,0,0xff);
      }
      *(uint *)(iVar10 + 0x360) = *(uint *)(iVar10 + 0x360) | 0x800000;
      param_3[0xc2] = (uint)FUN_802a514c;
      uVar7 = 2;
      goto LAB_8029eba4;
    }
  }
  else {
    if (0x40e < sVar2) goto LAB_8029e9b4;
    param_3[0xa8] = (uint)FLOAT_803e7f34;
    (**(code **)(*DAT_803dca8c + 0x20))(param_1,param_2,param_3,1);
    uVar8 = FUN_800217c0((double)*(float *)(iVar10 + 0x60c),(double)*(float *)(iVar10 + 0x614));
    *(undefined2 *)(iVar10 + 0x478) = uVar8;
    *(undefined2 *)(iVar10 + 0x484) = *(undefined2 *)(iVar10 + 0x478);
    FUN_802931a0((double)(*(float *)(iVar10 + 0x60c) * *(float *)(iVar10 + 0x60c) +
                         *(float *)(iVar10 + 0x614) * *(float *)(iVar10 + 0x614)));
    *(undefined2 *)(param_2 + 2) = 0;
    if (*(char *)((int)param_3 + 0x346) != '\0') {
      FUN_80030334((double)FLOAT_803e7ea4,param_2,0x40d,0);
    }
  }
  FUN_80247778((double)*(float *)(iVar10 + 0x640),iVar10 + 0x634,auStack48);
  FUN_80247730(iVar10 + 0x61c,auStack48,param_2 + 0xc);
  FUN_802ab5a4(param_2,iVar10,7);
  uVar7 = 0;
LAB_8029eba4:
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  return uVar7;
}

