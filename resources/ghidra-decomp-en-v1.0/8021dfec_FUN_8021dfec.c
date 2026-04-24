// Function: FUN_8021dfec
// Entry: 8021dfec
// Size: 1064 bytes

/* WARNING: Removing unreachable block (ram,0x8021e3e4) */
/* WARNING: Removing unreachable block (ram,0x8021e3ec) */

undefined4 FUN_8021dfec(double param_1,short *param_2,uint *param_3)

{
  float fVar1;
  bool bVar2;
  short sVar4;
  uint uVar3;
  short *psVar5;
  undefined4 uVar6;
  uint uVar7;
  int iVar8;
  bool bVar9;
  undefined4 uVar10;
  double dVar11;
  double dVar12;
  undefined8 in_f30;
  undefined8 in_f31;
  double local_40;
  double local_38;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar10 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  iVar8 = *(int *)(param_2 + 0x5c);
  bVar2 = true;
  *param_3 = *param_3 | 0x200000;
  if ((float)param_3[0xa6] < FLOAT_803e6b04) {
    *(undefined2 *)(param_3 + 0xcd) = 0;
    *(undefined2 *)((int)param_3 + 0x336) = 0;
    param_3[0xa6] = (uint)FLOAT_803e6aa8;
  }
  uVar7 = (uint)*(short *)((int)param_3 + 0x336);
  uVar3 = uVar7;
  if ((int)uVar7 < 0) {
    uVar3 = -uVar7;
  }
  if ((int)*(short *)(iVar8 + 0xc16) < (int)uVar3) {
    *param_2 = *param_2 +
               ((short)(int)(FLOAT_803e6b08 *
                            (float)((double)(float)((double)CONCAT44(0x43300000,uVar7 ^ 0x80000000)
                                                   - DOUBLE_803e6af8) * param_1)) >> 5);
  }
  else {
    local_40 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
    *param_2 = (short)(int)(FLOAT_803e6b0c *
                            ((float)((double)(float)(local_40 - DOUBLE_803e6af8) * param_1) /
                            FLOAT_803e6b10) +
                           (float)((double)CONCAT44(0x43300000,(int)*param_2 ^ 0x80000000) -
                                  DOUBLE_803e6af8));
  }
  local_38 = (double)CONCAT44(0x43300000,(int)*(short *)((int)param_3 + 0x336) ^ 0x80000000);
  fVar1 = FLOAT_803e6b08 * (float)((double)(float)(local_38 - DOUBLE_803e6af8) * param_1);
  psVar5 = (short *)FUN_800395d8(param_2,9);
  if (psVar5 != (short *)0x0) {
    psVar5[1] = psVar5[1] + (short)((int)(short)(int)fVar1 - (int)psVar5[1] >> 3);
    *psVar5 = *psVar5 + (short)(-(int)*psVar5 >> 3);
    sVar4 = psVar5[1];
    if (sVar4 < -0x1555) {
      sVar4 = -0x1555;
    }
    else if (0x1555 < sVar4) {
      sVar4 = 0x1555;
    }
    psVar5[1] = sVar4;
    sVar4 = psVar5[1];
    if (sVar4 < -0x1555) {
      sVar4 = -0x1555;
    }
    else if (0x1555 < sVar4) {
      sVar4 = 0x1555;
    }
    psVar5[1] = sVar4;
  }
  fVar1 = (float)param_3[0xa6];
  if ((float)param_3[0xa6] < FLOAT_803e6aa8) {
    fVar1 = FLOAT_803e6aa8;
  }
  if (FLOAT_803e6ab8 < fVar1) {
    fVar1 = FLOAT_803e6ab8;
  }
  dVar12 = (double)(FLOAT_803e6adc * fVar1);
  if ((double)(FLOAT_803e6adc * fVar1) < (double)FLOAT_803e6aa8) {
    dVar12 = (double)FLOAT_803e6aa8;
  }
  param_3[0xa5] =
       (uint)(float)(param_1 * (double)((float)(dVar12 - (double)(float)param_3[0xa5]) /
                                       (float)param_3[0xae]) + (double)(float)param_3[0xa5]);
  uVar3 = (uint)param_2[1];
  if ((int)uVar3 < 1) {
    local_40 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
    dVar11 = (double)FUN_80293e80((double)((FLOAT_803e6b18 * (float)(local_40 - DOUBLE_803e6af8)) /
                                          FLOAT_803e6b1c));
    dVar12 = (double)FLOAT_803e6b20 * dVar11 - dVar12;
  }
  else {
    local_38 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
    dVar11 = (double)FUN_80293e80((double)((FLOAT_803e6b18 * (float)(local_38 - DOUBLE_803e6af8)) /
                                          FLOAT_803e6b1c));
    dVar12 = (double)FLOAT_803e6b14 * dVar11 - dVar12;
  }
  param_3[0xa0] =
       (uint)(float)(param_1 * (double)((float)(-(double)(float)dVar12 -
                                               (double)(float)param_3[0xa0]) / (float)param_3[0xae])
                    + (double)(float)param_3[0xa0]);
  bVar9 = false;
  dVar12 = (double)*(float *)(param_2 + 0x4c);
  psVar5 = &DAT_803dc32c;
  for (uVar3 = 0; (param_2[0x50] != *psVar5 && (uVar3 < 2)); uVar3 = uVar3 + 1) {
    psVar5 = psVar5 + 1;
  }
  if (1 < uVar3) {
    uVar3 = 0;
  }
  iVar8 = uVar3 << 1;
LAB_8021e39c:
  do {
    if (!bVar2) {
      if (bVar9) {
        FUN_80030334(dVar12,param_2,(int)(short)(&DAT_803dc32c)[uVar3],0);
        FUN_8002f574(param_2,10);
      }
      FUN_8002f5d4((double)(float)param_3[0xa0],param_2,param_3 + 0xa8);
      uVar6 = 0;
LAB_8021e3e4:
      __psq_l0(auStack8,uVar10);
      __psq_l1(auStack8,uVar10);
      __psq_l0(auStack24,uVar10);
      __psq_l1(auStack24,uVar10);
      return uVar6;
    }
    if ((float)param_3[0xa5] < (float)(&DAT_8032abb0)[iVar8]) {
      if (uVar3 == 1) {
        uVar6 = 2;
        goto LAB_8021e3e4;
      }
      uVar3 = uVar3 - 1;
      iVar8 = iVar8 + -2;
      bVar9 = true;
      goto LAB_8021e39c;
    }
    if ((float)param_3[0xa5] < (float)(&DAT_8032abb4)[iVar8]) {
      bVar2 = false;
    }
    else {
      if (uVar3 == 0) {
        dVar12 = (double)FLOAT_803e6aa8;
      }
      uVar3 = uVar3 + 1;
      iVar8 = iVar8 + 2;
      bVar9 = true;
    }
  } while( true );
}

