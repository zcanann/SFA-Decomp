// Function: FUN_801c2278
// Entry: 801c2278
// Size: 824 bytes

/* WARNING: Removing unreachable block (ram,0x801c2580) */
/* WARNING: Removing unreachable block (ram,0x801c2570) */
/* WARNING: Removing unreachable block (ram,0x801c2560) */
/* WARNING: Removing unreachable block (ram,0x801c2568) */
/* WARNING: Removing unreachable block (ram,0x801c2578) */
/* WARNING: Removing unreachable block (ram,0x801c2588) */

void FUN_801c2278(int param_1)

{
  float fVar1;
  short sVar2;
  int iVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  undefined4 uVar7;
  undefined8 uVar8;
  double dVar9;
  undefined8 in_f26;
  undefined8 in_f27;
  undefined8 in_f28;
  double dVar10;
  double dVar11;
  undefined8 in_f29;
  double dVar12;
  double dVar13;
  undefined8 in_f30;
  double dVar14;
  double dVar15;
  undefined8 in_f31;
  double dVar16;
  int local_78;
  int local_74;
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
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
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  __psq_st0(auStack72,(int)((ulonglong)in_f27 >> 0x20),0);
  __psq_st1(auStack72,(int)in_f27,0);
  __psq_st0(auStack88,(int)((ulonglong)in_f26 >> 0x20),0);
  __psq_st1(auStack88,(int)in_f26,0);
  iVar6 = *(int *)(param_1 + 0x4c);
  piVar4 = *(int **)(param_1 + 0xb8);
  if ((*(byte *)(iVar6 + 0x18) & 1) != 0) {
    iVar5 = *piVar4;
    if (iVar5 == 0) {
      piVar4 = (int *)FUN_8002e0fc(&local_78,&local_74);
      local_78 = 0;
      while ((local_78 < local_74 && (iVar5 == 0))) {
        iVar3 = *piVar4;
        if ((*(short *)(iVar3 + 0x44) == 0x36) &&
           ((uint)*(byte *)(iVar6 + 0x18) == *(byte *)(*(int *)(iVar3 + 0x4c) + 0x18) - 1)) {
          iVar5 = iVar3;
        }
        piVar4 = piVar4 + 1;
        local_78 = local_78 + 1;
      }
      if (iVar5 == 0) goto LAB_801c2560;
      **(int **)(iVar5 + 0xb8) = param_1;
      piVar4 = *(int **)(param_1 + 0xb8);
      *piVar4 = iVar5;
      dVar10 = (double)(*(float *)(iVar5 + 0xc) - *(float *)(param_1 + 0xc));
      dVar12 = (double)(*(float *)(iVar5 + 0x10) - *(float *)(param_1 + 0x10));
      dVar14 = (double)(*(float *)(iVar5 + 0x14) - *(float *)(param_1 + 0x14));
      uVar8 = FUN_802931a0((double)(float)(dVar14 * dVar14 +
                                          (double)(float)(dVar10 * dVar10 +
                                                         (double)(float)(dVar12 * dVar12))));
      sVar2 = FUN_800217c0(dVar10,dVar14);
      if (0x8000 < sVar2) {
        sVar2 = sVar2 + 1;
      }
      if (sVar2 < -0x8000) {
        sVar2 = sVar2 + -1;
      }
      *(short *)(piVar4 + 6) = sVar2;
      dVar9 = (double)FLOAT_803e4dfc;
      iVar6 = FUN_801c1238(dVar9,dVar9,dVar9,dVar10,dVar12,dVar14,uVar8,
                           (double)*(float *)(&DAT_803dbf50 + (uint)*(byte *)(iVar6 + 0x1b) * 4),
                           0x10);
      piVar4[0xb] = iVar6;
      piVar4[1] = *(int *)(param_1 + 0xc);
      piVar4[3] = *(int *)(param_1 + 0x14);
      piVar4[2] = *(int *)(iVar5 + 0xc);
      piVar4[4] = *(int *)(iVar5 + 0x14);
      fVar1 = (float)piVar4[1];
      if ((float)piVar4[2] < fVar1) {
        piVar4[1] = piVar4[2];
        piVar4[2] = (int)fVar1;
      }
      fVar1 = (float)piVar4[3];
      if ((float)piVar4[4] < fVar1) {
        piVar4[3] = piVar4[4];
        piVar4[4] = (int)fVar1;
      }
      fVar1 = FLOAT_803e4e24;
      piVar4[1] = (int)((float)piVar4[1] - FLOAT_803e4e24);
      piVar4[3] = (int)((float)piVar4[3] - fVar1);
      piVar4[2] = (int)((float)piVar4[2] + fVar1);
      piVar4[4] = (int)((float)piVar4[4] + fVar1);
      dVar16 = (double)*(float *)(param_1 + 0xc);
      dVar15 = (double)*(float *)(param_1 + 0x10);
      dVar13 = (double)*(float *)(param_1 + 0x14);
      dVar10 = (double)*(float *)(iVar5 + 0xc);
      dVar12 = (double)*(float *)(iVar5 + 0x10);
      dVar14 = (double)*(float *)(iVar5 + 0x14);
      dVar9 = (double)(float)((double)FLOAT_803e4e28 + dVar15);
      dVar11 = (double)(float)(dVar9 * (double)(float)(dVar13 - dVar14) +
                              (double)(float)(dVar15 * (double)(float)(dVar14 - dVar13) +
                                             (double)(float)(dVar12 * (double)(float)(dVar13 - 
                                                  dVar13))));
      dVar14 = (double)(float)(dVar13 * (double)(float)(dVar16 - dVar10) +
                              (double)(float)(dVar13 * (double)(float)(dVar10 - dVar16) +
                                             (double)(float)(dVar14 * (double)(float)(dVar16 - 
                                                  dVar16))));
      dVar12 = (double)(float)(dVar16 * (double)(float)(dVar15 - dVar12) +
                              (double)(float)(dVar16 * (double)(float)(dVar12 - dVar9) +
                                             (double)(float)(dVar10 * (double)(float)(dVar9 - dVar15
                                                                                     ))));
      dVar10 = (double)FUN_802931a0((double)(float)(dVar12 * dVar12 +
                                                   (double)(float)(dVar11 * dVar11 +
                                                                  (double)(float)(dVar14 * dVar14)))
                                   );
      if ((double)FLOAT_803e4dfc < dVar10) {
        dVar11 = (double)(float)(dVar11 / dVar10);
        dVar14 = (double)(float)(dVar14 / dVar10);
        dVar12 = (double)(float)(dVar12 / dVar10);
      }
      piVar4[7] = (int)(float)dVar11;
      piVar4[8] = (int)(float)dVar14;
      piVar4[9] = (int)(float)dVar12;
      piVar4[10] = (int)-(float)(dVar13 * dVar12 +
                                (double)(float)(dVar16 * dVar11 + (double)(float)(dVar15 * dVar14)))
      ;
    }
    FUN_801c0fd8(piVar4[0xb]);
  }
LAB_801c2560:
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  __psq_l0(auStack24,uVar7);
  __psq_l1(auStack24,uVar7);
  __psq_l0(auStack40,uVar7);
  __psq_l1(auStack40,uVar7);
  __psq_l0(auStack56,uVar7);
  __psq_l1(auStack56,uVar7);
  __psq_l0(auStack72,uVar7);
  __psq_l1(auStack72,uVar7);
  __psq_l0(auStack88,uVar7);
  __psq_l1(auStack88,uVar7);
  return;
}

