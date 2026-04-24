// Function: FUN_80030688
// Entry: 80030688
// Size: 1124 bytes

/* WARNING: Removing unreachable block (ram,0x80030ac4) */
/* WARNING: Removing unreachable block (ram,0x80030ab4) */
/* WARNING: Removing unreachable block (ram,0x80030aa4) */
/* WARNING: Removing unreachable block (ram,0x80030a9c) */
/* WARNING: Removing unreachable block (ram,0x80030aac) */
/* WARNING: Removing unreachable block (ram,0x80030abc) */
/* WARNING: Removing unreachable block (ram,0x80030acc) */

void FUN_80030688(undefined8 param_1,double param_2,double param_3,undefined4 param_4,
                 undefined4 param_5,int *param_6,int *param_7,int **param_8,float *param_9)

{
  double dVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float *pfVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int *piVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  float *pfVar15;
  int iVar16;
  undefined4 uVar17;
  double extraout_f1;
  double dVar18;
  double dVar19;
  double dVar20;
  undefined8 in_f25;
  double dVar21;
  undefined8 in_f26;
  undefined8 in_f27;
  undefined8 in_f28;
  undefined8 in_f29;
  double dVar22;
  undefined8 in_f30;
  double dVar23;
  undefined8 in_f31;
  double dVar24;
  undefined8 uVar25;
  float *local_e8;
  float local_e4;
  float *local_e0;
  float *local_dc;
  float local_d8;
  float local_d4;
  float *local_d0;
  float local_cc;
  float local_c8;
  float *local_c4;
  float local_c0;
  float local_bc;
  undefined auStack104 [16];
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar17 = 0;
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
  __psq_st0(auStack104,(int)((ulonglong)in_f25 >> 0x20),0);
  __psq_st1(auStack104,(int)in_f25,0);
  uVar25 = FUN_802860b4();
  pfVar5 = (float *)((ulonglong)uVar25 >> 0x20);
  iVar9 = (int)uVar25;
  iVar12 = 0;
  if (iVar9 == 0) {
    uVar6 = 0;
  }
  else {
    iVar11 = *param_6;
    iVar14 = *(int *)(iVar9 + 4);
    dVar22 = (double)(float)(extraout_f1 + extraout_f1);
    *param_8 = param_7;
    *param_9 = FLOAT_803de910;
    dVar21 = extraout_f1;
    iVar7 = FUN_8002856c(param_6,0);
    local_c4 = *(float **)(iVar7 + 0xc);
    local_c0 = *(float *)(iVar7 + 0x1c);
    local_bc = *(float *)(iVar7 + 0x2c);
    dVar18 = (double)FUN_802931a0((double)((local_bc - pfVar5[2]) * (local_bc - pfVar5[2]) +
                                          ((float)local_c4 - *pfVar5) * ((float)local_c4 - *pfVar5)
                                          + FLOAT_803de910));
    dVar18 = (double)(float)(dVar18 - dVar21);
    dVar24 = (double)(*pfVar5 + *pfVar5);
    dVar23 = (double)(pfVar5[2] + pfVar5[2]);
    uVar6 = (uint)*(byte *)(iVar11 + 0xf3);
    iVar7 = uVar6 * 4;
    iVar16 = uVar6 * 0x1c;
    pfVar15 = (float *)(iVar14 + iVar7);
    piVar10 = param_7;
    while( true ) {
      iVar7 = iVar7 + -4;
      iVar16 = iVar16 + -0x1c;
      pfVar15 = pfVar15 + -1;
      uVar6 = uVar6 - 1;
      if (uVar6 == 0) break;
      if (dVar18 < (double)*(float *)(*(int *)(iVar9 + 0x10) + iVar7)) {
        iVar13 = (int)*(char *)(*(int *)(iVar11 + 0x3c) + iVar16);
        iVar8 = FUN_8002856c(param_6,uVar6);
        local_c4 = *(float **)(iVar8 + 0xc);
        local_c0 = *(float *)(iVar8 + 0x1c);
        local_bc = *(float *)(iVar8 + 0x2c);
        iVar8 = FUN_8002856c(param_6,iVar13);
        local_d0 = *(float **)(iVar8 + 0xc);
        local_cc = *(float *)(iVar8 + 0x1c);
        local_c8 = *(float *)(iVar8 + 0x2c);
        *(undefined *)(*(int *)(iVar9 + 0x18) + uVar6) = 1;
        *(undefined *)(*(int *)(iVar9 + 0x18) + iVar13) = 1;
        dVar19 = (double)*pfVar15;
        dVar20 = (double)*(float *)(iVar14 + iVar13 * 4);
        if ((((double)(float)((double)local_c0 - dVar19) <= param_2) ||
            ((double)(float)((double)local_cc - dVar20) <= param_2)) &&
           ((param_3 <= (double)(float)((double)local_c0 + dVar19) ||
            (param_3 <= (double)(float)((double)local_cc + dVar20))))) {
          fVar3 = (float)((double)((float)local_d0 + (float)local_c4) - dVar24);
          fVar4 = (float)((double)(local_c8 + local_bc) - dVar23);
          if (dVar19 <= dVar20) {
            dVar1 = dVar20 + dVar20;
          }
          else {
            dVar1 = dVar19 + dVar19;
          }
          fVar2 = (float)(dVar22 + (double)(*(float *)(*(int *)(iVar9 + 0xc) + iVar7) + (float)dVar1
                                           ));
          if (fVar4 * fVar4 + fVar3 * fVar3 + FLOAT_803de910 < fVar2 * fVar2) {
            local_dc = (float *)((float)local_d0 - (float)local_c4);
            local_d8 = local_cc - local_c0;
            local_d4 = local_c8 - local_bc;
            fVar3 = *(float *)(*(int *)(iVar9 + 0xc) + iVar7);
            if (fVar3 != FLOAT_803de910) {
              fVar3 = FLOAT_803de918 / fVar3;
              local_dc = (float *)((float)local_dc * fVar3);
              local_d8 = local_d8 * fVar3;
              local_d4 = local_d4 * fVar3;
            }
            *(undefined *)(*(int *)(iVar9 + 0x18) + uVar6) = 0;
            *(undefined *)(*(int *)(iVar9 + 0x18) + iVar13) = 0;
            iVar8 = FUN_80032090(dVar21,dVar19,dVar20,
                                 (double)*(float *)(*(int *)(iVar9 + 0xc) + iVar7),pfVar5,&local_c4,
                                 &local_dc,&local_d0,&local_e0,&local_e4,&local_e8);
            if (iVar8 != 0) {
              *(undefined *)(*(int *)(iVar9 + 0x18) + uVar6) = 1;
              *(undefined *)(*(int *)(iVar9 + 0x18) + iVar13) = 1;
              dVar19 = (double)FUN_802931a0((double)local_e4);
              piVar10[0xc] = (int)(float)(dVar21 + (double)(float)(dVar19 - (double)(float)local_e8)
                                         );
              if (FLOAT_803de910 == (float)piVar10[0xc]) {
                piVar10[0xc] = (int)FLOAT_803de920;
              }
              fVar3 = (float)piVar10[0xc];
              if (fVar3 <= FLOAT_803de910) {
                fVar3 = -fVar3;
              }
              piVar10[0xf] = (int)(FLOAT_803de918 / fVar3);
              *param_9 = *param_9 + (float)piVar10[0xf];
              if ((float)piVar10[0xc] < (float)(*param_8)[0xc]) {
                *param_8 = piVar10;
              }
              *piVar10 = (int)&local_c4;
              piVar10[1] = (int)&local_d0;
              piVar10[2] = (int)local_c4;
              piVar10[3] = (int)local_c0;
              piVar10[4] = (int)local_bc;
              piVar10[5] = (int)local_d0;
              piVar10[6] = (int)local_cc;
              piVar10[7] = (int)local_c8;
              piVar10[0xb] = (int)local_e0;
              piVar10[0xe] = (int)local_e8;
              dVar19 = (double)FUN_802931a0((double)local_e4);
              piVar10[0xd] = (int)(float)dVar19;
              piVar10[8] = (int)local_dc;
              piVar10[9] = (int)local_d8;
              piVar10[10] = (int)local_d4;
              piVar10[0x10] = uVar6;
              piVar10[0x11] = iVar13;
              if (iVar12 < 0x13) {
                piVar10 = piVar10 + 0x12;
                iVar12 = iVar12 + 1;
              }
            }
          }
        }
      }
    }
    piVar10[0x10] = -1;
    uVar6 = (uint)((int)param_7 - (int)piVar10 | (int)piVar10 - (int)param_7) >> 0x1f;
  }
  __psq_l0(auStack8,uVar17);
  __psq_l1(auStack8,uVar17);
  __psq_l0(auStack24,uVar17);
  __psq_l1(auStack24,uVar17);
  __psq_l0(auStack40,uVar17);
  __psq_l1(auStack40,uVar17);
  __psq_l0(auStack56,uVar17);
  __psq_l1(auStack56,uVar17);
  __psq_l0(auStack72,uVar17);
  __psq_l1(auStack72,uVar17);
  __psq_l0(auStack88,uVar17);
  __psq_l1(auStack88,uVar17);
  __psq_l0(auStack104,uVar17);
  __psq_l1(auStack104,uVar17);
  FUN_80286100(uVar6);
  return;
}

