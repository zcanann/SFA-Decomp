// Function: FUN_802b98f0
// Entry: 802b98f0
// Size: 980 bytes

/* WARNING: Removing unreachable block (ram,0x802b9c94) */
/* WARNING: Removing unreachable block (ram,0x802b9c9c) */

undefined4 FUN_802b98f0(double param_1,short *param_2,uint *param_3)

{
  short sVar1;
  float fVar2;
  bool bVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  short *psVar7;
  undefined4 uVar8;
  bool bVar9;
  int iVar10;
  undefined4 uVar11;
  double dVar12;
  double dVar13;
  undefined8 in_f30;
  undefined8 in_f31;
  float local_58 [2];
  undefined4 local_50;
  uint uStack76;
  undefined4 local_48;
  uint uStack68;
  double local_40;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar11 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  local_58[0] = FLOAT_803e8240;
  iVar5 = FUN_80036e58(0x13,param_2,local_58);
  iVar10 = *(int *)(param_2 + 0x5c);
  iVar6 = FUN_8001ffb4(0x3e3);
  if ((iVar6 != 0) &&
     (iVar6 = FUN_8002208c((double)FLOAT_803e8244,(double)FLOAT_803e8248,iVar10 + 0xd04), iVar6 != 0
     )) {
    FUN_8000bb18(param_2,0x43a);
  }
  *param_3 = *param_3 | 0x200000;
  if ((float)param_3[0xa6] < FLOAT_803e824c) {
    *(undefined2 *)(param_3 + 0xcd) = 0;
    *(undefined2 *)((int)param_3 + 0x336) = 0;
    param_3[0xa6] = (uint)FLOAT_803e8234;
  }
  if (*(short *)(param_3 + 0xcd) < 0x5a) {
    uStack76 = (int)*(short *)((int)param_3 + 0x336) ^ 0x80000000;
    local_50 = 0x43300000;
    uStack68 = (int)*param_2 ^ 0x80000000;
    local_48 = 0x43300000;
    iVar6 = (int)(FLOAT_803e8250 *
                  ((float)((double)(float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e8270)
                          * param_1) / FLOAT_803e8254) +
                 (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e8270));
    local_40 = (double)(longlong)iVar6;
    *param_2 = (short)iVar6;
    fVar2 = (float)param_3[0xa6];
    if ((float)param_3[0xa6] < FLOAT_803e8234) {
      fVar2 = FLOAT_803e8234;
    }
    if (FLOAT_803e8258 < fVar2) {
      fVar2 = FLOAT_803e8258;
    }
    if (*(short *)(iVar10 + 0xa88) == 0) {
      fVar2 = FLOAT_803e8234;
    }
    dVar13 = (double)(FLOAT_803e825c * fVar2);
    if ((double)(FLOAT_803e825c * fVar2) < (double)FLOAT_803e8234) {
      dVar13 = (double)FLOAT_803e8234;
    }
    param_3[0xa5] =
         (uint)(float)(param_1 * (double)((float)(dVar13 - (double)(float)param_3[0xa5]) /
                                         (float)param_3[0xae]) + (double)(float)param_3[0xa5]);
    uVar4 = (uint)param_2[1];
    if ((int)uVar4 < 1) {
      uStack68 = uVar4 ^ 0x80000000;
      local_48 = 0x43300000;
      dVar12 = (double)FUN_80293e80((double)((FLOAT_803e8264 *
                                             (float)((double)CONCAT44(0x43300000,uStack68) -
                                                    DOUBLE_803e8270)) / FLOAT_803e8268));
      dVar13 = (double)FLOAT_803e826c * dVar12 - dVar13;
    }
    else {
      local_40 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      dVar12 = (double)FUN_80293e80((double)((FLOAT_803e8264 * (float)(local_40 - DOUBLE_803e8270))
                                            / FLOAT_803e8268));
      dVar13 = (double)FLOAT_803e8260 * dVar12 - dVar13;
    }
    dVar12 = -(double)(float)dVar13;
    if (-(double)(float)dVar13 < (double)DAT_80335130) {
      dVar12 = (double)DAT_80335130;
    }
    param_3[0xa0] =
         (uint)(float)(param_1 * (double)((float)(dVar12 - (double)(float)param_3[0xa0]) /
                                         (float)param_3[0xae]) + (double)(float)param_3[0xa0]);
    bVar9 = false;
    dVar13 = (double)*(float *)(param_2 + 0x4c);
    psVar7 = &DAT_803dc748;
    sVar1 = param_2[0x50];
    for (iVar6 = 0; (sVar1 != *psVar7 && (iVar6 < 2)); iVar6 = iVar6 + 1) {
      psVar7 = psVar7 + 1;
    }
    if (1 < iVar6) {
      iVar6 = 0;
    }
    if (sVar1 == 0x208) {
      iVar6 = 1;
    }
    if ((float)(&DAT_80335128)[iVar6 * 2] <= (float)param_3[0xa5]) {
      if (*(float *)(iVar6 * 8 + -0x7fccaed4) <= (float)param_3[0xa5]) {
        if (iVar6 == 0) {
          dVar13 = (double)FLOAT_803e8234;
        }
        iVar6 = iVar6 + 1;
        bVar9 = true;
      }
    }
    else {
      if (iVar6 == 1) {
        uVar8 = 8;
        goto LAB_802b9c94;
      }
      iVar6 = iVar6 + -1;
      bVar9 = true;
    }
    bVar3 = true;
    if ((*(char *)((int)param_3 + 0x346) != '\0') && (sVar1 == 0x208)) {
      bVar9 = true;
      bVar3 = false;
    }
    if (bVar9) {
      if ((iVar6 == 1) && (bVar3)) {
        FUN_80030334(dVar13,param_2,0x208,0);
      }
      else {
        FUN_80030334(dVar13,param_2,(int)(short)(&DAT_803dc748)[iVar6],0);
      }
    }
    FUN_8002f5d4((double)(float)param_3[0xa0],param_2,param_3 + 0xa8);
    if (((param_3[199] & 0x100) == 0) || ((iVar5 != 0 && ((*(byte *)(iVar5 + 0xaf) & 4) != 0)))) {
      uVar8 = 0;
    }
    else {
      uVar8 = 0xc;
    }
  }
  else {
    uVar8 = 8;
  }
LAB_802b9c94:
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  __psq_l0(auStack24,uVar11);
  __psq_l1(auStack24,uVar11);
  return uVar8;
}

