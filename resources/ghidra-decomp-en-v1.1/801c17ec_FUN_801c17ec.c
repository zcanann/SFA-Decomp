// Function: FUN_801c17ec
// Entry: 801c17ec
// Size: 992 bytes

/* WARNING: Removing unreachable block (ram,0x801c1bac) */
/* WARNING: Removing unreachable block (ram,0x801c1ba4) */
/* WARNING: Removing unreachable block (ram,0x801c1b9c) */
/* WARNING: Removing unreachable block (ram,0x801c1b94) */
/* WARNING: Removing unreachable block (ram,0x801c1b8c) */
/* WARNING: Removing unreachable block (ram,0x801c1b84) */
/* WARNING: Removing unreachable block (ram,0x801c1b7c) */
/* WARNING: Removing unreachable block (ram,0x801c1b74) */
/* WARNING: Removing unreachable block (ram,0x801c1b6c) */
/* WARNING: Removing unreachable block (ram,0x801c1b64) */
/* WARNING: Removing unreachable block (ram,0x801c1b5c) */
/* WARNING: Removing unreachable block (ram,0x801c184c) */
/* WARNING: Removing unreachable block (ram,0x801c1844) */
/* WARNING: Removing unreachable block (ram,0x801c183c) */
/* WARNING: Removing unreachable block (ram,0x801c1834) */
/* WARNING: Removing unreachable block (ram,0x801c182c) */
/* WARNING: Removing unreachable block (ram,0x801c1824) */
/* WARNING: Removing unreachable block (ram,0x801c181c) */
/* WARNING: Removing unreachable block (ram,0x801c1814) */
/* WARNING: Removing unreachable block (ram,0x801c180c) */
/* WARNING: Removing unreachable block (ram,0x801c1804) */
/* WARNING: Removing unreachable block (ram,0x801c17fc) */

void FUN_801c17ec(undefined8 param_1,double param_2,double param_3,double param_4,double param_5,
                 double param_6,undefined8 param_7,double param_8)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  undefined4 *puVar5;
  float *pfVar6;
  float *pfVar7;
  int iVar8;
  float *pfVar9;
  int iVar10;
  double extraout_f1;
  double dVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  double dVar15;
  
  iVar3 = FUN_80286834();
  dVar15 = (double)(float)(param_4 - extraout_f1);
  dVar14 = (double)(float)(param_5 - param_2);
  dVar13 = (double)(float)(param_6 - param_3);
  dVar12 = extraout_f1;
  dVar11 = FUN_80293900((double)(float)(dVar13 * dVar13 +
                                       (double)(float)(dVar15 * dVar15 +
                                                      (double)(float)(dVar14 * dVar14))));
  uVar4 = iVar3 - 1U ^ 0x80000000;
  dVar15 = (double)(float)(dVar15 / (double)(float)((double)CONCAT44(0x43300000,uVar4) -
                                                   DOUBLE_803e5a88));
  dVar14 = (double)(float)(dVar14 / (double)(float)((double)CONCAT44(0x43300000,uVar4) -
                                                   DOUBLE_803e5a88));
  dVar13 = (double)(float)(dVar13 / (double)(float)((double)CONCAT44(0x43300000,uVar4) -
                                                   DOUBLE_803e5a88));
  puVar5 = (undefined4 *)FUN_80023d8c(iVar3 * 0x34 + (iVar3 - 1U) * 0x24 + 0x44,0xff);
  *puVar5 = puVar5 + 0x11;
  puVar5[1] = puVar5 + iVar3 * 0xd + 0x11;
  *(char *)(puVar5 + 2) = (char)iVar3;
  puVar5[9] = (float)dVar11;
  puVar5[3] = (float)dVar12;
  puVar5[4] = (float)param_2;
  puVar5[5] = (float)param_3;
  puVar5[6] = (float)param_4;
  puVar5[7] = (float)param_5;
  puVar5[8] = (float)param_6;
  *(undefined *)(puVar5 + 0xd) = 0;
  *(undefined *)((int)puVar5 + 0x35) = 1;
  puVar5[0xe] = FLOAT_803e5a98;
  puVar5[10] = 1;
  puVar5[0xc] = FLOAT_803e5a90;
  if ((double)FLOAT_803e5a9c < (double)(float)((double)(float)puVar5[0xc] * dVar11)) {
    puVar5[0xc] = (float)((double)FLOAT_803e5a9c / dVar11);
  }
  puVar5[0xb] = FLOAT_803e5aa0;
  puVar5[0x10] = (float)((double)(float)puVar5[0xc] / param_8);
  puVar5[0xf] = (float)((double)FLOAT_803e5aa4 / param_8);
  fVar1 = FLOAT_803e5a94;
  dVar12 = DOUBLE_803e5a88;
  pfVar9 = (float *)*puVar5;
  uVar4 = 0;
  pfVar7 = pfVar9;
  iVar10 = iVar3;
  if (0 < iVar3) {
    do {
      uVar2 = uVar4 ^ 0x80000000;
      *pfVar7 = (float)((double)(float)((double)CONCAT44(0x43300000,uVar2) - dVar12) * dVar15 +
                       (double)(float)puVar5[3]);
      pfVar7[1] = (float)((double)(float)((double)CONCAT44(0x43300000,uVar2) - dVar12) * dVar14 +
                         (double)(float)puVar5[4]);
      pfVar7[2] = (float)((double)(float)((double)CONCAT44(0x43300000,uVar2) - dVar12) * dVar13 +
                         (double)(float)puVar5[5]);
      pfVar7[5] = fVar1;
      pfVar7[4] = fVar1;
      pfVar7[3] = fVar1;
      pfVar7[8] = fVar1;
      pfVar7[7] = fVar1;
      pfVar7[6] = fVar1;
      *(undefined *)(pfVar7 + 0xc) = 0;
      if ((uVar4 == 0) || (uVar4 == iVar3 - 1U)) {
        *(undefined *)(pfVar7 + 9) = 1;
      }
      else if ((uVar4 == 1) || (uVar4 == iVar3 - 2U)) {
        *(undefined *)(pfVar7 + 9) = 2;
      }
      else {
        *(undefined *)(pfVar7 + 9) = 2;
      }
      pfVar6 = pfVar7;
      for (iVar8 = 0; iVar8 < (int)(uint)*(byte *)(pfVar7 + 9); iVar8 = iVar8 + 1) {
        pfVar6[10] = 0.0;
        pfVar6 = pfVar6 + 1;
      }
      pfVar7 = pfVar7 + 0xd;
      uVar4 = uVar4 + 1;
      iVar10 = iVar10 + -1;
    } while (iVar10 != 0);
  }
  *(undefined *)(pfVar9 + iVar3 * 0xd + -1) = 1;
  *(undefined *)(pfVar9 + 0xc) = 1;
  iVar8 = puVar5[1];
  dVar14 = (double)FLOAT_803e5aa8;
  dVar13 = (double)FLOAT_803e5a94;
  dVar11 = (double)FLOAT_803e5aac;
  pfVar7 = pfVar9;
  dVar12 = DOUBLE_803e5a88;
  for (iVar10 = 0; iVar10 < (int)(iVar3 - 1U); iVar10 = iVar10 + 1) {
    *(float *)(iVar8 + 0xc) =
         (float)puVar5[9] / (float)((double)CONCAT44(0x43300000,iVar3 - 1U ^ 0x80000000) - dVar12);
    *(float *)(iVar8 + 0x10) = (float)dVar14;
    *(float *)(iVar8 + 0x20) = (float)dVar13;
    *(float *)(iVar8 + 0x1c) = (float)dVar13;
    *(float *)(iVar8 + 0x18) = (float)dVar13;
    *(float *)(iVar8 + 0x14) = (float)(dVar11 * (double)*(float *)(iVar8 + 0xc));
    FUN_801c176c(iVar8,(int)pfVar7,(int)(pfVar9 + (iVar10 + 1) * 0xd));
    iVar8 = iVar8 + 0x24;
    pfVar7 = pfVar7 + 0xd;
  }
  FUN_80286880();
  return;
}

