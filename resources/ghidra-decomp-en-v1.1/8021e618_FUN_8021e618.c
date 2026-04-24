// Function: FUN_8021e618
// Entry: 8021e618
// Size: 1088 bytes

/* WARNING: Removing unreachable block (ram,0x8021ea30) */
/* WARNING: Removing unreachable block (ram,0x8021ea28) */
/* WARNING: Removing unreachable block (ram,0x8021e630) */
/* WARNING: Removing unreachable block (ram,0x8021e628) */

undefined4
FUN_8021e618(double param_1,undefined8 param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  bool bVar2;
  short sVar3;
  uint uVar4;
  undefined4 uVar5;
  short *psVar6;
  uint uVar7;
  int iVar8;
  int iVar9;
  double dVar10;
  double dVar11;
  undefined8 local_40;
  undefined8 local_38;
  
  iVar9 = *(int *)(param_9 + 0x5c);
  bVar2 = true;
  uVar4 = FUN_80020078(0x631);
  if (uVar4 == 0) {
    *param_10 = *param_10 | 0x200000;
    if ((float)param_10[0xa6] < FLOAT_803e779c) {
      *(undefined2 *)(param_10 + 0xcd) = 0;
      *(undefined2 *)((int)param_10 + 0x336) = 0;
      param_10[0xa6] = (uint)FLOAT_803e7740;
    }
    uVar7 = (uint)*(short *)((int)param_10 + 0x336);
    uVar4 = uVar7;
    if ((int)uVar7 < 0) {
      uVar4 = -uVar7;
    }
    if ((int)*(short *)(iVar9 + 0xc16) < (int)uVar4) {
      *param_9 = *param_9 +
                 ((short)(int)(FLOAT_803e77a0 *
                              (float)((double)(float)((double)CONCAT44(0x43300000,uVar7 ^ 0x80000000
                                                                      ) - DOUBLE_803e7790) * param_1
                                     )) >> 5);
    }
    else {
      param_3 = (double)FLOAT_803e77a4;
      local_40 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
      *param_9 = (short)(int)(param_3 * (double)((float)((double)(float)(local_40 - DOUBLE_803e7790)
                                                        * param_1) / FLOAT_803e77a8) +
                             (double)(float)((double)CONCAT44(0x43300000,(int)*param_9 ^ 0x80000000)
                                            - DOUBLE_803e7790));
    }
    local_38 = (double)CONCAT44(0x43300000,(int)*(short *)((int)param_10 + 0x336) ^ 0x80000000);
    fVar1 = FLOAT_803e77a0 * (float)((double)(float)(local_38 - DOUBLE_803e7790) * param_1);
    psVar6 = (short *)FUN_800396d0((int)param_9,9);
    if (psVar6 != (short *)0x0) {
      psVar6[1] = psVar6[1] + (short)((int)(short)(int)fVar1 - (int)psVar6[1] >> 3);
      *psVar6 = *psVar6 + (short)(-(int)*psVar6 >> 3);
      sVar3 = psVar6[1];
      if (sVar3 < -0x1555) {
        sVar3 = -0x1555;
      }
      else if (0x1555 < sVar3) {
        sVar3 = 0x1555;
      }
      psVar6[1] = sVar3;
      sVar3 = psVar6[1];
      if (sVar3 < -0x1555) {
        sVar3 = -0x1555;
      }
      else if (0x1555 < sVar3) {
        sVar3 = 0x1555;
      }
      psVar6[1] = sVar3;
    }
    fVar1 = (float)param_10[0xa6];
    if ((float)param_10[0xa6] < FLOAT_803e7740) {
      fVar1 = FLOAT_803e7740;
    }
    if (FLOAT_803e7750 < fVar1) {
      fVar1 = FLOAT_803e7750;
    }
    dVar11 = (double)(FLOAT_803e7774 * fVar1);
    if ((double)(FLOAT_803e7774 * fVar1) < (double)FLOAT_803e7740) {
      dVar11 = (double)FLOAT_803e7740;
    }
    param_10[0xa5] =
         (uint)(float)(param_1 * (double)((float)(dVar11 - (double)(float)param_10[0xa5]) /
                                         (float)param_10[0xae]) + (double)(float)param_10[0xa5]);
    if (param_9[1] < 1) {
      dVar10 = (double)FUN_802945e0();
      dVar11 = (double)FLOAT_803e77b8 * dVar10 - dVar11;
    }
    else {
      dVar10 = (double)FUN_802945e0();
      dVar11 = (double)FLOAT_803e77ac * dVar10 - dVar11;
    }
    dVar10 = (double)(float)param_10[0xa0];
    param_10[0xa0] =
         (uint)(float)(param_1 * (double)((float)(-(double)(float)dVar11 - dVar10) /
                                         (float)param_10[0xae]) + dVar10);
    iVar9 = 0;
    dVar11 = (double)*(float *)(param_9 + 0x4c);
    psVar6 = &DAT_803dcf94;
    for (uVar4 = 0; (param_9[0x50] != *psVar6 && (uVar4 < 2)); uVar4 = uVar4 + 1) {
      psVar6 = psVar6 + 1;
    }
    if (1 < uVar4) {
      uVar4 = 0;
    }
    iVar8 = uVar4 << 1;
    while (bVar2) {
      dVar10 = (double)(float)param_10[0xa5];
      if ((double)(float)(&DAT_8032b808)[iVar8] <= dVar10) {
        if (dVar10 < (double)(float)(&DAT_8032b80c)[iVar8]) {
          bVar2 = false;
        }
        else {
          if (uVar4 == 0) {
            dVar11 = (double)FLOAT_803e7740;
          }
          uVar4 = uVar4 + 1;
          iVar8 = iVar8 + 2;
          iVar9 = 1;
        }
      }
      else {
        if (uVar4 == 1) {
          return 2;
        }
        uVar4 = uVar4 - 1;
        iVar8 = iVar8 + -2;
        iVar9 = 1;
      }
    }
    if (iVar9 != 0) {
      FUN_8003042c(dVar11,dVar10,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                   (int)(short)(&DAT_803dcf94)[uVar4],0,iVar9,param_13,param_14,param_15,param_16);
      FUN_8002f66c((int)param_9,10);
    }
    FUN_8002f6cc((double)(float)param_10[0xa0],(int)param_9,(float *)(param_10 + 0xa8));
    uVar5 = 0;
  }
  else {
    uVar5 = 8;
  }
  return uVar5;
}

