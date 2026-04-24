// Function: FUN_80246fd0
// Entry: 80246fd0
// Size: 248 bytes

/* WARNING: Removing unreachable block (ram,0x802470a4) */
/* WARNING: Removing unreachable block (ram,0x80247090) */
/* WARNING: Removing unreachable block (ram,0x80246fe4) */
/* WARNING: Removing unreachable block (ram,0x80246fd8) */
/* WARNING: Removing unreachable block (ram,0x80246fd0) */
/* WARNING: Removing unreachable block (ram,0x80246fd4) */
/* WARNING: Removing unreachable block (ram,0x80246fe0) */
/* WARNING: Removing unreachable block (ram,0x80246fec) */
/* WARNING: Removing unreachable block (ram,0x80247098) */
/* WARNING: Removing unreachable block (ram,0x802470c0) */

undefined4 FUN_80246fd0(int param_1,int param_2)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  float fVar10;
  float fVar11;
  float fVar12;
  float fVar13;
  float fVar14;
  float fVar15;
  
  fVar1 = (float)__psq_l0(param_1,0);
  fVar2 = (float)__psq_l0(param_1 + 4,0);
  fVar3 = (float)__psq_l1(param_1 + 4,0);
  fVar4 = (float)__psq_l0(param_1 + 0x10,0);
  fVar5 = (float)__psq_l0(param_1 + 0x14,0);
  fVar6 = (float)__psq_l1(param_1 + 0x14,0);
  fVar7 = (float)__psq_l0(param_1 + 0x20,0);
  fVar8 = (float)__psq_l0(param_1 + 0x24,0);
  fVar9 = (float)__psq_l1(param_1 + 0x24,0);
  fVar11 = fVar2 * fVar6 - fVar5 * fVar3;
  fVar12 = fVar3 * fVar4 - fVar6 * fVar1;
  fVar14 = fVar5 * fVar9 - fVar8 * fVar6;
  fVar15 = fVar6 * fVar7 - fVar9 * fVar4;
  fVar13 = fVar8 * fVar3 - fVar2 * fVar9;
  fVar9 = fVar9 * fVar1 - fVar3 * fVar7;
  fVar6 = fVar7 * fVar11 + fVar4 * fVar13 + fVar1 * fVar14;
  if (fVar6 != fVar3 - fVar3) {
    fVar3 = (float)((ulonglong)
                    (double)(float)(1.0 / (double)CONCAT44(fVar6,fVar12 * 1.0 +
                                                                 fVar9 * 1.0 + fVar15 * 1.0)) >>
                   0x20);
    fVar3 = -(fVar6 * fVar3 * fVar3 - (fVar3 + fVar3));
    fVar14 = fVar14 * fVar3;
    fVar15 = fVar15 * fVar3;
    fVar13 = fVar13 * fVar3;
    fVar9 = fVar9 * fVar3;
    fVar11 = fVar11 * fVar3;
    fVar12 = fVar12 * fVar3;
    fVar10 = (fVar4 * fVar8 - fVar5 * fVar7) * fVar3;
    fVar7 = (fVar2 * fVar7 - fVar1 * fVar8) * fVar3;
    __psq_st0(param_2,fVar14,0);
    __psq_st1(param_2,fVar13,0);
    fVar6 = (float)((ulonglong)(double)*(float *)(param_1 + 0xc) >> 0x20);
    __psq_st0(param_2 + 0x10,fVar15,0);
    __psq_st1(param_2 + 0x10,fVar9,0);
    fVar3 = (fVar1 * fVar5 - fVar2 * fVar4) * fVar3;
    fVar1 = (float)((ulonglong)(double)*(float *)(param_1 + 0x1c) >> 0x20);
    __psq_st0(param_2 + 0x20,fVar10,0);
    fVar2 = (float)((ulonglong)(double)*(float *)(param_1 + 0x2c) >> 0x20);
    __psq_st0(param_2 + 0x24,fVar7,0);
    __psq_st0(param_2 + 0x28,fVar3,0);
    __psq_st0(param_2 + 8,fVar11,0);
    __psq_st1(param_2 + 8,-(fVar11 * fVar2 + fVar13 * fVar1 + fVar14 * fVar6),0);
    __psq_st0(param_2 + 0x18,fVar12,0);
    __psq_st1(param_2 + 0x18,
              -(fVar12 * SUB84((double)*(float *)(param_1 + 0x2c),0) +
               fVar9 * SUB84((double)*(float *)(param_1 + 0x1c),0) +
               fVar15 * SUB84((double)*(float *)(param_1 + 0xc),0)),0);
    __psq_st0(param_2 + 0x2c,-(fVar3 * fVar2 + fVar7 * fVar1 + fVar10 * fVar6),0);
    return 1;
  }
  return 0;
}

