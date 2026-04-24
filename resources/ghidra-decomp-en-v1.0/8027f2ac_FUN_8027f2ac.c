// Function: FUN_8027f2ac
// Entry: 8027f2ac
// Size: 1944 bytes

void FUN_8027f2ac(double param_1,double param_2,double param_3,char param_4,float *param_5,
                 uint param_6,uint param_7,int param_8,int param_9)

{
  float *pfVar1;
  float *pfVar2;
  float *pfVar3;
  float *pfVar4;
  float fVar5;
  float fVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  float *pfVar12;
  float *pfVar13;
  float *pfVar14;
  float *pfVar15;
  int unaff_r26;
  int unaff_r27;
  undefined *puVar16;
  double dVar17;
  double dVar18;
  double dVar19;
  double dVar20;
  double dVar21;
  double dVar22;
  double in_f23;
  double dVar23;
  double in_f24;
  double dVar24;
  double dVar25;
  
  puVar16 = &DAT_8032fdb8;
  if (param_4 != '\0') {
    puVar16 = &DAT_8032fb9c;
  }
  if (param_6 == 0x800000) {
    param_6 = 0;
    param_7 = 0x7f0000;
  }
  if (param_6 < 0x10001) {
    iVar7 = 0;
  }
  else {
    iVar7 = param_6 - 0x10000;
  }
  if (param_7 < 0x10001) {
    iVar11 = 0;
  }
  else {
    iVar11 = param_7 - 0x10000;
  }
  dVar18 = (double)(FLOAT_803e7870 * (float)((double)CONCAT44(0x43300000,iVar7) - DOUBLE_803e7868));
  dVar20 = (double)(FLOAT_803e7870 * (float)((double)CONCAT44(0x43300000,iVar11) - DOUBLE_803e7868))
  ;
  if (param_9 != 0) {
    in_f24 = dVar18;
    if (ABS((double)FLOAT_803e785c) <= ABS(dVar18)) {
      FUN_8028660c((double)(float)(dVar18 / (double)FLOAT_803e785c));
      dVar21 = (double)FUN_802864b8();
      in_f24 = (double)(float)(dVar18 - (double)(float)((double)FLOAT_803e785c * dVar21));
    }
    unaff_r26 = FUN_80285fb4(dVar18);
    dVar21 = (double)(float)((double)FLOAT_803e7874 - dVar18);
    in_f23 = dVar21;
    if (ABS((double)FLOAT_803e785c) <= ABS(dVar21)) {
      FUN_8028660c((double)(float)(dVar21 / (double)FLOAT_803e785c));
      dVar17 = (double)FUN_802864b8();
      in_f23 = (double)(float)(dVar21 - (double)(float)((double)FLOAT_803e785c * dVar17));
    }
    unaff_r27 = FUN_80285fb4(dVar21);
  }
  if (param_8 != 0) {
    dVar18 = (double)(float)((double)FLOAT_803e785c +
                            (double)(FLOAT_803e7878 * (float)(dVar18 - (double)FLOAT_803e785c)));
  }
  dVar21 = dVar18;
  if (ABS((double)FLOAT_803e785c) <= ABS(dVar18)) {
    FUN_8028660c((double)(float)(dVar18 / (double)FLOAT_803e785c));
    dVar21 = (double)FUN_802864b8();
    dVar21 = (double)(float)(dVar18 - (double)(float)((double)FLOAT_803e785c * dVar21));
  }
  iVar7 = FUN_80285fb4(dVar18);
  dVar17 = dVar20;
  if (ABS((double)FLOAT_803e785c) <= ABS(dVar20)) {
    FUN_8028660c((double)(float)(dVar20 / (double)FLOAT_803e785c));
    dVar17 = (double)FUN_802864b8();
    dVar17 = (double)(float)(dVar20 - (double)(float)((double)FLOAT_803e785c * dVar17));
  }
  iVar11 = FUN_80285fb4(dVar20);
  dVar22 = (double)(float)((double)FLOAT_803e7874 - dVar18);
  dVar20 = (double)(float)((double)FLOAT_803e7874 - dVar20);
  dVar18 = dVar22;
  if (ABS((double)FLOAT_803e785c) <= ABS(dVar22)) {
    FUN_8028660c((double)(float)(dVar22 / (double)FLOAT_803e785c));
    dVar18 = (double)FUN_802864b8();
    dVar18 = (double)(float)(dVar22 - (double)(float)((double)FLOAT_803e785c * dVar18));
  }
  iVar8 = FUN_80285fb4(dVar22);
  dVar22 = dVar20;
  if (ABS((double)FLOAT_803e785c) <= ABS(dVar20)) {
    FUN_8028660c((double)(float)(dVar20 / (double)FLOAT_803e785c));
    dVar22 = (double)FUN_802864b8();
    dVar22 = (double)(float)(dVar20 - (double)(float)((double)FLOAT_803e785c * dVar22));
  }
  iVar9 = FUN_80285fb4(dVar20);
  if (param_9 == 0) {
    dVar19 = (double)(float)((double)FLOAT_803e7858 * param_1);
    iVar10 = FUN_80285fb4(dVar19);
    dVar20 = (double)FLOAT_803e785c;
    dVar24 = (double)(float)(dVar20 - dVar17);
    dVar19 = (double)(float)(dVar19 - (double)(float)((double)CONCAT44(0x43300000,iVar10) -
                                                     DOUBLE_803e7868));
    pfVar12 = (float *)(&DAT_8032ffc0 + iVar11 * 4);
    pfVar1 = (float *)(&DAT_8032ffbc + iVar11 * 4);
    dVar25 = (double)(float)(dVar20 - dVar22);
    pfVar13 = (float *)(&DAT_8032ffc0 + iVar9 * 4);
    pfVar14 = (float *)(&DAT_8032ffc0 + iVar7 * 4);
    fVar5 = (float)(dVar20 - dVar19) * *(float *)(puVar16 + iVar10 * 4) +
            (float)(dVar19 * (double)*(float *)(puVar16 + iVar10 * 4 + 4));
    dVar19 = (double)(float)(dVar20 - dVar21);
    pfVar15 = (float *)(&DAT_8032ffc0 + iVar8 * 4);
    dVar20 = (double)(float)(dVar20 - dVar18);
    param_5[2] = FLOAT_803e7860 *
                 fVar5 * ((float)(dVar24 * (double)*pfVar1) + (float)(dVar17 * (double)*pfVar12));
    pfVar2 = (float *)(&DAT_8032ffbc + iVar9 * 4);
    pfVar3 = (float *)(&DAT_8032ffbc + iVar7 * 4);
    fVar5 = fVar5 * ((float)(dVar25 * (double)*pfVar2) + (float)(dVar22 * (double)*pfVar13));
    param_5[1] = fVar5 * ((float)(dVar19 * (double)*pfVar3) + (float)(dVar21 * (double)*pfVar14));
    pfVar4 = (float *)(&DAT_8032ffbc + iVar8 * 4);
    *param_5 = fVar5 * ((float)(dVar20 * (double)*pfVar4) + (float)(dVar18 * (double)*pfVar15));
    dVar23 = (double)(float)((double)FLOAT_803e7858 * param_2);
    iVar7 = FUN_80285fb4(dVar23);
    fVar5 = (float)(dVar23 - (double)(float)((double)CONCAT44(0x43300000,iVar7) - DOUBLE_803e7868));
    fVar5 = (FLOAT_803e785c - fVar5) * *(float *)(puVar16 + iVar7 * 4) +
            fVar5 * *(float *)(puVar16 + iVar7 * 4 + 4);
    param_5[5] = FLOAT_803e7860 *
                 fVar5 * ((float)(dVar24 * (double)*pfVar1) + (float)(dVar17 * (double)*pfVar12));
    fVar5 = fVar5 * ((float)(dVar25 * (double)*pfVar2) + (float)(dVar22 * (double)*pfVar13));
    param_5[4] = fVar5 * ((float)(dVar19 * (double)*pfVar3) + (float)(dVar21 * (double)*pfVar14));
    param_5[3] = fVar5 * ((float)(dVar20 * (double)*pfVar4) + (float)(dVar18 * (double)*pfVar15));
    dVar23 = (double)(float)((double)FLOAT_803e7858 * param_3);
    iVar7 = FUN_80285fb4(dVar23);
    fVar5 = (float)(dVar23 - (double)(float)((double)CONCAT44(0x43300000,iVar7) - DOUBLE_803e7868));
    fVar5 = (FLOAT_803e785c - fVar5) * *(float *)(puVar16 + iVar7 * 4) +
            fVar5 * *(float *)(puVar16 + iVar7 * 4 + 4);
    param_5[8] = FLOAT_803e7860 *
                 fVar5 * ((float)(dVar24 * (double)*pfVar1) + (float)(dVar17 * (double)*pfVar12));
    fVar5 = fVar5 * ((float)(dVar25 * (double)*pfVar2) + (float)(dVar22 * (double)*pfVar13));
    param_5[7] = fVar5 * ((float)(dVar19 * (double)*pfVar3) + (float)(dVar21 * (double)*pfVar14));
    param_5[6] = fVar5 * ((float)(dVar20 * (double)*pfVar4) + (float)(dVar18 * (double)*pfVar15));
  }
  else {
    dVar19 = (double)(float)((double)FLOAT_803e7858 * param_1);
    iVar10 = FUN_80285fb4(dVar19);
    dVar20 = (double)FLOAT_803e785c;
    dVar23 = (double)(float)(dVar20 - dVar17);
    dVar24 = (double)(float)(dVar20 - dVar22);
    dVar19 = (double)(float)(dVar19 - (double)(float)((double)CONCAT44(0x43300000,iVar10) -
                                                     DOUBLE_803e7868));
    dVar25 = (double)(float)(dVar20 - dVar21);
    fVar5 = (float)(dVar20 - dVar19) * *(float *)(puVar16 + iVar10 * 4) +
            (float)(dVar19 * (double)*(float *)(puVar16 + iVar10 * 4 + 4));
    dVar19 = (double)(float)(dVar20 - dVar18);
    fVar6 = fVar5 * ((float)(dVar23 * (double)*(float *)(&DAT_8032ffbc + iVar11 * 4)) +
                    (float)(dVar17 * (double)*(float *)(&DAT_8032ffc0 + iVar11 * 4)));
    fVar5 = fVar5 * ((float)(dVar24 * (double)*(float *)(&DAT_8032ffbc + iVar9 * 4)) +
                    (float)(dVar22 * (double)*(float *)(&DAT_8032ffc0 + iVar9 * 4)));
    param_5[1] = fVar5 * ((float)(dVar25 * (double)*(float *)(&DAT_8032ffbc + iVar7 * 4)) +
                         (float)(dVar21 * (double)*(float *)(&DAT_8032ffc0 + iVar7 * 4)));
    *param_5 = fVar5 * ((float)(dVar19 * (double)*(float *)(&DAT_8032ffbc + iVar8 * 4)) +
                       (float)(dVar18 * (double)*(float *)(&DAT_8032ffc0 + iVar8 * 4)));
    param_5[7] = fVar6 * ((float)(dVar20 - in_f24) * *(float *)(&DAT_8032ffcc + unaff_r26 * 4) +
                         (float)(in_f24 * (double)*(float *)(&DAT_8032ffc0 + unaff_r26 * 4)));
    param_5[6] = fVar6 * ((float)(dVar20 - in_f23) * *(float *)(&DAT_8032ffcc + unaff_r27 * 4) +
                         (float)(in_f23 * (double)*(float *)(&DAT_8032ffc0 + unaff_r27 * 4)));
    dVar20 = (double)(float)((double)FLOAT_803e7858 * param_2);
    iVar10 = FUN_80285fb4(dVar20);
    fVar5 = (float)(dVar20 - (double)(float)((double)CONCAT44(0x43300000,iVar10) - DOUBLE_803e7868))
    ;
    fVar5 = (FLOAT_803e785c - fVar5) * *(float *)(puVar16 + iVar10 * 4) +
            fVar5 * *(float *)(puVar16 + iVar10 * 4 + 4);
    param_5[5] = FLOAT_803e7860 *
                 fVar5 * ((float)(dVar23 * (double)*(float *)(&DAT_8032ffbc + iVar11 * 4)) +
                         (float)(dVar17 * (double)*(float *)(&DAT_8032ffc0 + iVar11 * 4)));
    fVar5 = fVar5 * ((float)(dVar24 * (double)*(float *)(&DAT_8032ffbc + iVar9 * 4)) +
                    (float)(dVar22 * (double)*(float *)(&DAT_8032ffc0 + iVar9 * 4)));
    param_5[4] = fVar5 * ((float)(dVar25 * (double)*(float *)(&DAT_8032ffbc + iVar7 * 4)) +
                         (float)(dVar21 * (double)*(float *)(&DAT_8032ffc0 + iVar7 * 4)));
    param_5[3] = fVar5 * ((float)(dVar19 * (double)*(float *)(&DAT_8032ffbc + iVar8 * 4)) +
                         (float)(dVar18 * (double)*(float *)(&DAT_8032ffc0 + iVar8 * 4)));
    fVar5 = FLOAT_803e787c;
    param_5[2] = FLOAT_803e787c;
    param_5[8] = fVar5;
  }
  return;
}

