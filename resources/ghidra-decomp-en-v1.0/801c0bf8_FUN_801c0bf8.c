// Function: FUN_801c0bf8
// Entry: 801c0bf8
// Size: 616 bytes

/* WARNING: Removing unreachable block (ram,0x801c0e38) */
/* WARNING: Removing unreachable block (ram,0x801c0e30) */
/* WARNING: Removing unreachable block (ram,0x801c0e40) */

void FUN_801c0bf8(undefined4 param_1,undefined4 param_2,float *param_3,float *param_4,short *param_5
                 )

{
  short sVar1;
  short sVar2;
  short sVar3;
  short sVar4;
  short sVar5;
  short sVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  float fVar10;
  float fVar11;
  float fVar12;
  undefined4 uVar13;
  short extraout_r4;
  int iVar14;
  short *psVar15;
  undefined4 uVar16;
  double dVar17;
  undefined8 in_f29;
  double dVar18;
  undefined8 in_f30;
  double dVar19;
  undefined8 in_f31;
  double dVar20;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar16 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  uVar13 = FUN_802860c8();
  fVar7 = FLOAT_803e4de0 * *param_3;
  fVar8 = FLOAT_803e4de0 * param_3[1];
  fVar9 = FLOAT_803e4de0 * param_3[2];
  fVar10 = FLOAT_803e4de0 * *param_4;
  fVar11 = FLOAT_803e4de0 * param_4[1];
  fVar12 = FLOAT_803e4de0 * param_4[2];
  FUN_80003494(param_5,uVar13,0x60);
  iVar14 = 0;
  dVar19 = (double)((FLOAT_803e4de4 *
                    (float)((double)CONCAT44(0x43300000,(int)extraout_r4 ^ 0x80000000) -
                           DOUBLE_803e4df0)) / FLOAT_803e4de8);
  psVar15 = param_5;
  dVar20 = DOUBLE_803e4df0;
  do {
    dVar18 = (double)(float)((double)CONCAT44(0x43300000,(int)*psVar15 ^ 0x80000000) - dVar20);
    dVar17 = (double)FUN_80294204(dVar19);
    *psVar15 = (short)(int)(dVar18 * dVar17);
    dVar17 = (double)FUN_80293e80(dVar19);
    psVar15[2] = (short)(int)(-dVar18 * dVar17);
    psVar15 = psVar15 + 8;
    iVar14 = iVar14 + 1;
  } while (iVar14 < 6);
  sVar1 = (short)(int)fVar7;
  *param_5 = *param_5 + sVar1;
  sVar2 = (short)(int)fVar8;
  param_5[1] = param_5[1] + sVar2;
  sVar3 = (short)(int)fVar9;
  param_5[2] = param_5[2] + sVar3;
  sVar4 = (short)(int)fVar10;
  param_5[0x18] = param_5[0x18] + sVar4;
  sVar5 = (short)(int)fVar11;
  param_5[0x19] = param_5[0x19] + sVar5;
  sVar6 = (short)(int)fVar12;
  param_5[0x1a] = param_5[0x1a] + sVar6;
  param_5[8] = param_5[8] + sVar1;
  param_5[9] = param_5[9] + sVar2;
  param_5[10] = param_5[10] + sVar3;
  param_5[0x20] = param_5[0x20] + sVar4;
  param_5[0x21] = param_5[0x21] + sVar5;
  param_5[0x22] = param_5[0x22] + sVar6;
  param_5[0x10] = param_5[0x10] + sVar1;
  param_5[0x11] = param_5[0x11] + sVar2;
  param_5[0x12] = param_5[0x12] + sVar3;
  param_5[0x28] = param_5[0x28] + sVar4;
  param_5[0x29] = param_5[0x29] + sVar5;
  param_5[0x2a] = param_5[0x2a] + sVar6;
  __psq_l0(auStack8,uVar16);
  __psq_l1(auStack8,uVar16);
  __psq_l0(auStack24,uVar16);
  __psq_l1(auStack24,uVar16);
  __psq_l0(auStack40,uVar16);
  __psq_l1(auStack40,uVar16);
  FUN_80286114();
  return;
}

