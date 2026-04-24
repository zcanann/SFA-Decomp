// Function: FUN_800386bc
// Entry: 800386bc
// Size: 716 bytes

/* WARNING: Removing unreachable block (ram,0x80038960) */
/* WARNING: Removing unreachable block (ram,0x80038950) */
/* WARNING: Removing unreachable block (ram,0x80038940) */
/* WARNING: Removing unreachable block (ram,0x80038948) */
/* WARNING: Removing unreachable block (ram,0x80038958) */
/* WARNING: Removing unreachable block (ram,0x80038968) */

void FUN_800386bc(undefined8 param_1,double param_2,double param_3)

{
  short *psVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int *piVar5;
  short sVar6;
  int iVar7;
  int iVar8;
  short *psVar9;
  int iVar10;
  undefined4 uVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  double dVar15;
  double dVar16;
  undefined8 in_f26;
  undefined8 in_f27;
  undefined8 in_f28;
  undefined8 in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar11 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  __psq_st0(auStack72,(int)((ulonglong)in_f27 >> 0x20),0);
  __psq_st1(auStack72,(int)in_f27,0);
  __psq_st0(auStack88,(int)((ulonglong)in_f26 >> 0x20),0);
  __psq_st1(auStack88,(int)in_f26,0);
  dVar12 = (double)FUN_802860d8();
  sVar6 = -1;
  piVar5 = (int *)FUN_8005afa0();
  iVar8 = 0;
  do {
    iVar10 = *piVar5;
    if (iVar10 != 0) {
      psVar9 = *(short **)(iVar10 + 0x20);
      for (iVar7 = 0; iVar7 < (int)(uint)*(ushort *)(iVar10 + 8);
          iVar7 = iVar7 + (uint)*(byte *)psVar1 * 4) {
        if (*psVar9 == 0x130) {
          dVar13 = (double)FUN_80293e80((double)((FLOAT_803de980 *
                                                 (float)((double)CONCAT44(0x43300000,
                                                                          (uint)*(byte *)(psVar9 + 
                                                  0x10) * -0x100 ^ 0x80000000) - DOUBLE_803de988)) /
                                                FLOAT_803de984));
          dVar14 = (double)FUN_80294204((double)((FLOAT_803de980 *
                                                 (float)((double)CONCAT44(0x43300000,
                                                                          (uint)*(byte *)(psVar9 + 
                                                  0x10) * -0x100 ^ 0x80000000) - DOUBLE_803de988)) /
                                                FLOAT_803de984));
          dVar15 = (double)FUN_80293e80((double)((FLOAT_803de980 *
                                                 (float)((double)CONCAT44(0x43300000,
                                                                          (uint)*(byte *)((int)
                                                  psVar9 + 0x21) * -0x100 ^ 0x80000000) -
                                                  DOUBLE_803de988)) / FLOAT_803de984));
          dVar16 = (double)FUN_80294204((double)((FLOAT_803de980 *
                                                 (float)((double)CONCAT44(0x43300000,
                                                                          (uint)*(byte *)((int)
                                                  psVar9 + 0x21) * -0x100 ^ 0x80000000) -
                                                  DOUBLE_803de988)) / FLOAT_803de984));
          fVar3 = (float)((double)(float)(dVar12 - (double)*(float *)(psVar9 + 4)) * dVar14 -
                         (double)(float)((double)(float)(param_3 - (double)*(float *)(psVar9 + 8)) *
                                        dVar13));
          dVar13 = (double)(float)((double)(float)(dVar12 - (double)*(float *)(psVar9 + 4)) * dVar13
                                  + (double)(float)((double)(float)(param_3 -
                                                                   (double)*(float *)(psVar9 + 8)) *
                                                   dVar14));
          fVar4 = (float)((double)(float)(param_2 - (double)*(float *)(psVar9 + 6)) * dVar16 -
                         (double)(float)(dVar13 * dVar15));
          fVar2 = (float)((double)(float)(param_2 - (double)*(float *)(psVar9 + 6)) * dVar15 +
                         (double)(float)(dVar13 * dVar16));
          if (fVar3 < FLOAT_803de970) {
            fVar3 = -fVar3;
          }
          if (fVar4 < FLOAT_803de970) {
            fVar4 = -fVar4;
          }
          if (fVar2 < FLOAT_803de970) {
            fVar2 = -fVar2;
          }
          if (fVar3 <= (float)((double)CONCAT44(0x43300000,(uint)(ushort)psVar9[0xd]) -
                              DOUBLE_803de990)) {
            if (fVar4 <= (float)((double)CONCAT44(0x43300000,(uint)(ushort)psVar9[0xe]) -
                                DOUBLE_803de990)) {
              if (fVar2 <= (float)((double)CONCAT44(0x43300000,(uint)(ushort)psVar9[0xf]) -
                                  DOUBLE_803de990)) {
                sVar6 = psVar9[0xc];
              }
            }
          }
        }
        psVar1 = psVar9 + 1;
        psVar9 = psVar9 + (uint)*(byte *)psVar1 * 2;
      }
    }
    piVar5 = piVar5 + 1;
    iVar8 = iVar8 + 1;
  } while (iVar8 < 0x50);
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  __psq_l0(auStack24,uVar11);
  __psq_l1(auStack24,uVar11);
  __psq_l0(auStack40,uVar11);
  __psq_l1(auStack40,uVar11);
  __psq_l0(auStack56,uVar11);
  __psq_l1(auStack56,uVar11);
  __psq_l0(auStack72,uVar11);
  __psq_l1(auStack72,uVar11);
  __psq_l0(auStack88,uVar11);
  __psq_l1(auStack88,uVar11);
  FUN_80286124(sVar6);
  return;
}

