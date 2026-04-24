// Function: FUN_80109778
// Entry: 80109778
// Size: 816 bytes

/* WARNING: Removing unreachable block (ram,0x80109a7c) */
/* WARNING: Removing unreachable block (ram,0x80109a74) */
/* WARNING: Removing unreachable block (ram,0x80109a84) */

void FUN_80109778(short *param_1)

{
  float fVar1;
  uint uVar2;
  uint uVar3;
  char cVar4;
  char cVar5;
  int iVar6;
  undefined4 uVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  undefined8 in_f29;
  double dVar11;
  undefined8 in_f30;
  undefined8 in_f31;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  dVar11 = (double)FLOAT_803e1840;
  iVar6 = *(int *)(param_1 + 0x52);
  uVar2 = FUN_80014ee8(0);
  uVar3 = FUN_80014e70(0);
  if ((uVar3 & 2) == 0) {
    if ((uVar2 & 8) != 0) {
      dVar11 = (double)(FLOAT_803e1844 * *DAT_803dd550);
    }
    if ((uVar2 & 4) != 0) {
      dVar11 = (double)(FLOAT_803e1848 * *DAT_803dd550);
    }
    dVar8 = dVar11;
    if (dVar11 < (double)FLOAT_803e1840) {
      dVar8 = -dVar11;
    }
    dVar10 = (double)DAT_803dd550[1];
    dVar9 = dVar10;
    if (dVar10 < (double)FLOAT_803e1840) {
      dVar9 = -dVar10;
    }
    fVar1 = FLOAT_803e1850;
    if (dVar8 < dVar9) {
      fVar1 = FLOAT_803e184c;
    }
    DAT_803dd550[1] = fVar1 * (float)(dVar11 - dVar10) + DAT_803dd550[1];
    *DAT_803dd550 = *DAT_803dd550 + DAT_803dd550[1];
    if (*DAT_803dd550 < FLOAT_803e1854) {
      *DAT_803dd550 = FLOAT_803e1854;
    }
    if (FLOAT_803e1858 < *DAT_803dd550) {
      *DAT_803dd550 = FLOAT_803e1858;
    }
    cVar4 = FUN_80014c18(0);
    cVar5 = FUN_80014bc4(0);
    *param_1 = *param_1 + cVar4 * -3;
    param_1[1] = param_1[1] + cVar5 * 3;
    dVar11 = (double)FUN_80293e80((double)((FLOAT_803e185c *
                                           (float)((double)CONCAT44(0x43300000,
                                                                    (int)*param_1 - 0x4000U ^
                                                                    0x80000000) - DOUBLE_803e1868))
                                          / FLOAT_803e1860));
    dVar8 = (double)FUN_80294204((double)((FLOAT_803e185c *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*param_1 - 0x4000U ^
                                                                   0x80000000) - DOUBLE_803e1868)) /
                                         FLOAT_803e1860));
    dVar9 = (double)FUN_80294204((double)((FLOAT_803e185c *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)param_1[1] ^ 0x80000000) -
                                                 DOUBLE_803e1868)) / FLOAT_803e1860));
    dVar10 = (double)FUN_80293e80((double)((FLOAT_803e185c *
                                           (float)((double)CONCAT44(0x43300000,
                                                                    (int)param_1[1] ^ 0x80000000) -
                                                  DOUBLE_803e1868)) / FLOAT_803e1860));
    fVar1 = *DAT_803dd550;
    dVar9 = (double)(float)((double)fVar1 * dVar9);
    *(float *)(param_1 + 0xc) = *(float *)(iVar6 + 0x18) + (float)(dVar9 * dVar8);
    *(float *)(param_1 + 0xe) =
         FLOAT_803e1854 + *(float *)(iVar6 + 0x1c) + (float)((double)fVar1 * dVar10);
    *(float *)(param_1 + 0x10) = *(float *)(iVar6 + 0x20) + (float)(dVar9 * dVar11);
    FUN_8000e034((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
                 (double)*(float *)(param_1 + 0x10),param_1 + 6,param_1 + 8,param_1 + 10,
                 *(undefined4 *)(param_1 + 0x18));
  }
  else {
    (**(code **)(*DAT_803dca50 + 0x1c))(0x42,0,1,0,0,0,0xff);
  }
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  __psq_l0(auStack24,uVar7);
  __psq_l1(auStack24,uVar7);
  __psq_l0(auStack40,uVar7);
  __psq_l1(auStack40,uVar7);
  return;
}

