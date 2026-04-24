// Function: FUN_802a5384
// Entry: 802a5384
// Size: 4880 bytes

/* WARNING: Removing unreachable block (ram,0x802a6664) */
/* WARNING: Removing unreachable block (ram,0x802a665c) */
/* WARNING: Removing unreachable block (ram,0x802a666c) */

int FUN_802a5384(int param_1,uint *param_2)

{
  bool bVar1;
  byte bVar2;
  byte bVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  short sVar7;
  int iVar8;
  uint uVar9;
  undefined uVar10;
  int iVar11;
  int iVar12;
  undefined4 uVar13;
  double dVar14;
  double dVar15;
  undefined8 in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
  double dVar16;
  double local_58;
  double local_50;
  double local_48;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar13 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  iVar12 = *(int *)(param_1 + 0xb8);
  *(byte *)(iVar12 + 0x3f1) = *(byte *)(iVar12 + 0x3f1) & 0xfd;
  *(byte *)(iVar12 + 0x3f1) = *(byte *)(iVar12 + 0x3f1) & 0xfb;
  *(byte *)(iVar12 + 0x3f1) = *(byte *)(iVar12 + 0x3f1) & 0xf7;
  *(byte *)(iVar12 + 0x3f2) = *(byte *)(iVar12 + 0x3f2) & 0xef;
  if (*(char *)((int)param_2 + 0x27a) != '\0') {
    *(uint *)(iVar12 + 0x360) = *(uint *)(iVar12 + 0x360) | 0x2000000;
    *(byte *)(iVar12 + 0x3f0) = *(byte *)(iVar12 + 0x3f0) & 0x7f;
    *(byte *)(iVar12 + 0x3f0) = *(byte *)(iVar12 + 0x3f0) & 0xbf;
    *(byte *)(iVar12 + 0x3f3) = *(byte *)(iVar12 + 0x3f3) & 0xbf;
    *(undefined *)(iVar12 + 0x8cc) = 0;
    *(undefined2 *)(iVar12 + 0x81e) = 0;
    *(byte *)(iVar12 + 0x3f2) = *(byte *)(iVar12 + 0x3f2) & 0xef | 0x10;
  }
  iVar8 = FUN_802ac7dc(param_1,param_2,iVar12);
  if (iVar8 != 0) goto LAB_802a665c;
  FUN_802ad204(param_1,iVar12);
  bVar2 = *(byte *)(iVar12 + 0x3f0);
  if ((bVar2 >> 5 & 1) == 0) {
    if ((*(byte *)(iVar12 + 0x3f1) >> 5 & 1) == 0) {
      if (((bVar2 >> 3 & 1) == 0) && ((bVar2 >> 2 & 1) == 0)) {
        *(uint *)(iVar12 + 0x360) = *(uint *)(iVar12 + 0x360) | 0x2000000;
        *param_2 = *param_2 | 0x800000;
        *(undefined2 *)(param_2 + 0x9e) = 0;
        *(float *)(iVar12 + 0x404) = FLOAT_803e806c;
      }
      else {
        *param_2 = *param_2 | 0x200000;
        *(uint *)(iVar12 + 0x360) = *(uint *)(iVar12 + 0x360) | 0x2000000;
        *(float *)(iVar12 + 0x404) = FLOAT_803e8068;
      }
    }
    else {
      *(uint *)(iVar12 + 0x360) = *(uint *)(iVar12 + 0x360) | 0x2000000;
      *param_2 = *param_2 | 0x800000;
      *(undefined2 *)(param_2 + 0x9e) = 0;
      *(float *)(iVar12 + 0x404) = FLOAT_803e7ed4;
    }
  }
  else {
    *param_2 = *param_2 | 0x200000;
    *(uint *)(iVar12 + 0x360) = *(uint *)(iVar12 + 0x360) | 0x2000;
    *(uint *)(iVar12 + 0x360) = *(uint *)(iVar12 + 0x360) | 0x2000000;
    *(undefined2 *)(param_2 + 0x9e) = 2;
    *(code **)(iVar12 + 0x898) = FUN_802a514c;
    if ((*(byte *)(iVar12 + 0x3f1) >> 5 & 1) == 0) {
      *(float *)(iVar12 + 0x404) = FLOAT_803e8064;
    }
    else {
      *(float *)(iVar12 + 0x404) = FLOAT_803e7f2c;
    }
  }
  if (*(char *)((int)param_2 + 0x27a) != '\0') {
    if (((*(byte *)(iVar12 + 0x3f1) >> 5 & 1) == 0) && ((*(byte *)(iVar12 + 0x3f0) >> 2 & 1) == 0))
    {
      *(short *)(iVar12 + 0x484) =
           *(short *)(iVar12 + 0x484) + (short)*(undefined4 *)(iVar12 + 0x48c) * 0xb6;
    }
    *(undefined4 *)(iVar12 + 0x488) = 0;
    *(undefined4 *)(iVar12 + 0x48c) = 0;
  }
  dVar14 = (double)(((float)param_2[0xa6] - FLOAT_803e7f14) / FLOAT_803e7f2c);
  dVar16 = (double)FLOAT_803e7ea4;
  if ((dVar16 <= dVar14) && (dVar16 = dVar14, (double)FLOAT_803e7ee0 < dVar14)) {
    dVar16 = (double)FLOAT_803e7ee0;
  }
  *(float *)(iVar12 + 0x408) =
       (*(float *)(iVar12 + 0x404) - FLOAT_803e7f6c) *
       (float)(dVar16 * (double)*(float *)(iVar12 + 0x840));
  bVar2 = *(byte *)(iVar12 + 0x3f0);
  if ((bVar2 >> 6 & 1) == 0) {
    if ((bVar2 >> 4 & 1) == 0) {
      if ((char)bVar2 < '\0') {
        iVar8 = FUN_802ae480(param_1,iVar12,param_2);
        if (iVar8 != 0) {
          param_2[0xc2] = (uint)FUN_802a514c;
          iVar8 = 2;
          goto LAB_802a665c;
        }
      }
      else if ((bVar2 >> 1 & 1) == 0) {
        if ((bVar2 >> 5 & 1) == 0) {
          if ((bVar2 >> 3 & 1) == 0) {
            if (((bVar2 >> 2 & 1) != 0) &&
               (iVar8 = FUN_802ad2f4(param_1,iVar12,param_2), iVar8 != 0)) {
              param_2[0xc2] = (uint)FUN_802a514c;
              iVar8 = 2;
              goto LAB_802a665c;
            }
          }
          else {
            FUN_802adc08(param_1,iVar12,param_2);
          }
        }
        else {
          FUN_802ade80(param_1,iVar12,param_2);
        }
      }
      else {
        *(uint *)(iVar12 + 0x360) = *(uint *)(iVar12 + 0x360) | 0x800;
        fVar4 = FLOAT_803e7ea4;
        param_2[0xa5] = (uint)FLOAT_803e7ea4;
        param_2[0xa5] = (uint)fVar4;
        param_2[0xa1] = (uint)fVar4;
        param_2[0xa0] = (uint)fVar4;
        *(float *)(param_1 + 0x24) = fVar4;
        *(float *)(param_1 + 0x28) = fVar4;
        *(float *)(param_1 + 0x2c) = fVar4;
        fVar5 = FLOAT_803e7fa4;
        *(float *)(iVar12 + 0x428) = FLOAT_803e7fa4;
        *(float *)(iVar12 + 0x42c) = fVar4;
        *(float *)(iVar12 + 0x430) = fVar5;
        *(float *)(iVar12 + 0x434) = fVar4;
        *(float *)(iVar12 + 0x408) = fVar4;
        uVar9 = FUN_80014dd8(0);
        if ((uVar9 & 0x20) == 0) {
LAB_802a58b8:
          if ((DAT_803de44c != 0) && ((*(byte *)(iVar12 + 0x3f4) >> 6 & 1) != 0)) {
            *(undefined *)(iVar12 + 0x8b4) = 1;
            *(byte *)(iVar12 + 0x3f4) = *(byte *)(iVar12 + 0x3f4) & 0xf7 | 8;
          }
          FUN_80170380(DAT_803de450,2);
          *(byte *)(iVar12 + 0x3f0) = *(byte *)(iVar12 + 0x3f0) & 0xfd;
          *(uint *)(iVar12 + 0x360) = *(uint *)(iVar12 + 0x360) | 0x800000;
          FUN_80035ea4(param_1);
          bVar1 = true;
        }
        else {
          if (((((*(byte *)(iVar12 + 0x3f4) >> 6 & 1) == 0) ||
               (bVar2 = *(byte *)(iVar12 + 0x3f0), (bVar2 >> 5 & 1) != 0)) ||
              ((bVar2 >> 3 & 1) != 0)) ||
             ((((((bVar2 >> 2 & 1) != 0 || (*(char *)(iVar12 + 0x8c8) == 'D')) ||
                ((*(int *)(iVar12 + 0x7f8) != 0 ||
                 ((*(int *)(iVar12 + 0x2d0) != 0 || ((*(byte *)(iVar12 + 0x3f6) >> 6 & 1) != 0))))))
               || (*(short *)(iVar12 + 0x274) == 0x26)) ||
              (((*(ushort *)(param_1 + 0xb0) & 0x1000) != 0 ||
               (*(float *)(iVar12 + 0x880) != FLOAT_803e7ea4)))))) {
            bVar1 = false;
          }
          else {
            bVar1 = true;
          }
          if (!bVar1) goto LAB_802a58b8;
          bVar1 = false;
        }
        if (bVar1) {
          param_2[0xc2] = (uint)FUN_802a514c;
          iVar8 = 2;
          goto LAB_802a665c;
        }
      }
    }
    else {
      FUN_802ae650(param_1,iVar12,param_2);
    }
  }
  else {
    *(uint *)(iVar12 + 0x360) = *(uint *)(iVar12 + 0x360) | 0x1000000;
    param_2[0xa8] = (uint)FLOAT_803e8070;
    local_58 = (double)CONCAT44(0x43300000,*(uint *)(iVar12 + 0x858) ^ 0x80000000);
    sVar7 = (short)(int)(FLOAT_803e7f98 * *(float *)(param_1 + 0x98) +
                        (float)(local_58 - DOUBLE_803e7ec0));
    *(short *)(iVar12 + 0x478) = sVar7;
    *(int *)(iVar12 + 0x494) = (int)sVar7;
    if (*(char *)((int)param_2 + 0x346) != '\0') {
      *(byte *)(iVar12 + 0x3f0) = *(byte *)(iVar12 + 0x3f0) & 0xbf;
      *(short *)(iVar12 + 0x478) = *(short *)(iVar12 + 0x484);
      *(int *)(iVar12 + 0x494) = (int)*(short *)(iVar12 + 0x484);
      *(undefined *)(iVar12 + 0x8cc) = 0xc;
      *(byte *)(iVar12 + 0x3f1) = *(byte *)(iVar12 + 0x3f1) & 0xfb | 4;
      *(byte *)(iVar12 + 0x3f1) = *(byte *)(iVar12 + 0x3f1) & 0xf7 | 8;
    }
    param_2[0xa5] = (uint)(*(float *)(iVar12 + 0x844) * FLOAT_803db414 + (float)param_2[0xa5]);
    *(float *)(iVar12 + 0x408) = FLOAT_803e7ea4;
    if ((FLOAT_803e7efc < *(float *)(param_1 + 0x98)) &&
       (*(float *)(param_1 + 0x98) < FLOAT_803e8074)) {
      *(ushort *)(iVar12 + 0x8d8) = *(ushort *)(iVar12 + 0x8d8) | 8;
    }
  }
  bVar2 = *(byte *)(iVar12 + 0x3f0);
  if ((((((bVar2 >> 5 & 1) == 0) && ((bVar2 >> 6 & 1) == 0)) && ((bVar2 >> 4 & 1) == 0)) &&
      (((bVar2 >> 2 & 1) == 0 && ((bVar2 >> 3 & 1) == 0)))) &&
     (((bVar2 >> 1 & 1) == 0 &&
      ((*(int *)(iVar12 + 0x7f8) == 0 && (*(char *)(iVar12 + 0x8c8) != 'D')))))) {
    bVar1 = true;
  }
  else {
    bVar1 = false;
  }
  if ((bVar1) && ((*(ushort *)(iVar12 + 0x6e2) & 0x400) != 0)) {
    FUN_802aed2c(param_1,iVar12,param_2);
  }
  bVar2 = *(byte *)(iVar12 + 0x3f0);
  if (((((bVar2 >> 5 & 1) == 0) && ((bVar2 >> 6 & 1) == 0)) && (-1 < (char)bVar2)) &&
     ((((bVar2 >> 4 & 1) == 0 && ((bVar2 >> 2 & 1) == 0)) &&
      (((bVar2 >> 3 & 1) == 0 && ((*(byte *)(iVar12 + 0x3f1) >> 5 & 1) == 0)))))) {
    bVar1 = true;
  }
  else {
    bVar1 = false;
  }
  if (((bVar1) &&
      (FLOAT_803e7eac + *(float *)(*(int *)(iVar12 + 0x400) + 0x14) < (float)param_2[0xa5])) &&
     ((*(float *)(iVar12 + 0x470) < FLOAT_803e8030 || (0x95 < *(int *)(iVar12 + 0x488))))) {
    *(ushort *)(iVar12 + 0x8d8) = *(ushort *)(iVar12 + 0x8d8) | 8;
    *(byte *)(iVar12 + 0x3f0) = *(byte *)(iVar12 + 0x3f0) & 0x7f | 0x80;
    *(undefined *)(iVar12 + 0x8a6) = *(undefined *)(iVar12 + 0x8a7);
    *(uint *)(iVar12 + 0x360) = *(uint *)(iVar12 + 0x360) | 0x1000000;
    *(uint *)(iVar12 + 0x844) = param_2[0xa0];
    FUN_80030334((double)FLOAT_803e7ea4,param_1,(int)*(short *)(*(int *)(iVar12 + 0x3f8) + 0x3c),0);
  }
  if (((-1 < (char)*(byte *)(iVar12 + 0x3f0)) && ((*(byte *)(iVar12 + 0x3f0) >> 6 & 1) == 0)) &&
     ((*(byte *)(iVar12 + 0x3f1) >> 5 & 1) == 0)) {
    if (*(int *)(iVar12 + 0x488) < 0x96) {
      local_50 = (double)CONCAT44(0x43300000,*(uint *)(iVar12 + 0x47c) ^ 0x80000000);
      dVar14 = (double)FUN_80021370((double)(float)(local_50 - DOUBLE_803e7ec0),
                                    (double)(FLOAT_803e7ee0 / *(float *)(iVar12 + 0x428)),
                                    (double)FLOAT_803db414);
      dVar15 = (double)(FLOAT_803db414 * *(float *)(iVar12 + 0x42c) * *(float *)(iVar12 + 0x420));
      if (dVar15 < dVar14) {
        dVar14 = dVar15;
      }
      if (*(int *)(iVar12 + 0x480) < 0) {
        dVar14 = -dVar14;
      }
      local_58 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar12 + 0x478) ^ 0x80000000);
      *(short *)(iVar12 + 0x478) =
           (short)(int)((double)FLOAT_803e7f00 * dVar14 +
                       (double)(float)(local_58 - DOUBLE_803e7ec0));
    }
    if ((int)*(uint *)(iVar12 + 0x488) < 0x96) {
      local_48 = (double)CONCAT44(0x43300000,*(uint *)(iVar12 + 0x488) ^ 0x80000000);
      dVar14 = (double)FUN_80021370((double)(float)(local_48 - DOUBLE_803e7ec0),
                                    (double)(FLOAT_803e7ee0 / *(float *)(iVar12 + 0x430)),
                                    (double)FLOAT_803db414);
      dVar15 = (double)(*(float *)(iVar12 + 0x434) * FLOAT_803db414);
      if (dVar15 < dVar14) {
        dVar14 = dVar15;
      }
      if (*(int *)(iVar12 + 0x48c) < 0) {
        dVar14 = -dVar14;
      }
      local_50 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar12 + 0x484) ^ 0x80000000);
      *(short *)(iVar12 + 0x484) =
           (short)(int)((double)FLOAT_803e7f00 * dVar14 +
                       (double)(float)(local_50 - DOUBLE_803e7ec0));
    }
    else {
      bVar2 = *(byte *)(iVar12 + 0x3f0);
      if ((((bVar2 >> 3 & 1) == 0) && ((bVar2 >> 2 & 1) == 0)) &&
         (((bVar2 >> 4 & 1) == 0 &&
          (((float)param_2[0xa5] <= *(float *)(*(int *)(iVar12 + 0x400) + 4) &&
           ((float)param_2[0xa0] <= *(float *)(*(int *)(iVar12 + 0x400) + 0xc))))))) {
        *(short *)(iVar12 + 0x484) =
             *(short *)(iVar12 + 0x484) + (short)*(undefined4 *)(iVar12 + 0x48c) * 0xb6;
      }
    }
  }
  bVar2 = *(byte *)(iVar12 + 0x3f1);
  if ((bVar2 >> 5 & 1) == 0) {
    bVar3 = *(byte *)(iVar12 + 0x3f0);
    if (((((((bVar3 >> 6 & 1) == 0) && ((bVar2 >> 2 & 1) == 0)) && ((bVar3 >> 4 & 1) == 0)) &&
         (((bVar2 >> 1 & 1) == 0 && ((bVar3 >> 3 & 1) == 0)))) && ((bVar3 >> 2 & 1) == 0)) &&
       ((bVar3 >> 1 & 1) == 0)) {
      dVar14 = (double)FUN_80021370((double)(*(float *)(iVar12 + 0x408) - (float)param_2[0xa5]),
                                    (double)*(float *)(iVar12 + 0x438),(double)FLOAT_803db414);
      dVar16 = (double)(FLOAT_803e7ea8 * FLOAT_803db414);
      if ((dVar16 <= dVar14) &&
         (dVar16 = dVar14, (double)(FLOAT_803e7efc * FLOAT_803db414) < dVar14)) {
        dVar16 = (double)(FLOAT_803e7efc * FLOAT_803db414);
      }
      if ((0x95 < *(int *)(iVar12 + 0x488)) && ((double)FLOAT_803e7ea4 < dVar16)) {
        dVar16 = (double)(float)((double)FLOAT_803e7ed4 * -dVar16);
      }
      param_2[0xa5] = (uint)(float)((double)(float)param_2[0xa5] + dVar16);
      fVar4 = (float)param_2[0xa5];
      fVar5 = **(float **)(iVar12 + 0x400);
      if ((fVar5 <= fVar4) && (fVar5 = fVar4, *(float *)(iVar12 + 0x404) < fVar4)) {
        fVar5 = *(float *)(iVar12 + 0x404);
      }
      param_2[0xa5] = (uint)fVar5;
      param_2[0xa1] = (uint)FLOAT_803e7ea4;
    }
    else if (((*(byte *)(iVar12 + 0x3f0) >> 3 & 1) == 0) &&
            ((*(byte *)(iVar12 + 0x3f0) >> 2 & 1) == 0)) {
      fVar4 = (float)param_2[0xa5];
      fVar5 = *(float *)(iVar12 + 0x404);
      fVar6 = -fVar5;
      if ((fVar6 <= fVar4) && (fVar6 = fVar4, fVar5 < fVar4)) {
        fVar6 = fVar5;
      }
      param_2[0xa5] = (uint)fVar6;
    }
    else {
      local_48 = (double)CONCAT44(0x43300000,*(uint *)(iVar12 + 0x48c) ^ 0x80000000);
      dVar16 = (double)FUN_80293e80((double)((FLOAT_803e7f94 *
                                             FLOAT_803e7f00 * (float)(local_48 - DOUBLE_803e7ec0)) /
                                            FLOAT_803e7f98));
      dVar14 = (double)(float)((double)*(float *)(iVar12 + 0x408) * -dVar16);
      local_50 = (double)CONCAT44(0x43300000,*(uint *)(iVar12 + 0x48c) ^ 0x80000000);
      dVar16 = (double)FUN_80294204((double)((FLOAT_803e7f94 *
                                             FLOAT_803e7f00 * (float)(local_50 - DOUBLE_803e7ec0)) /
                                            FLOAT_803e7f98));
      dVar16 = (double)(float)((double)*(float *)(iVar12 + 0x408) * dVar16);
      if ((*(byte *)(iVar12 + 0x3f0) >> 2 & 1) == 0) {
        param_2[0xa5] = (uint)-(FLOAT_803e7f20 * FLOAT_803db414 - (float)param_2[0xa5]);
      }
      else {
        dVar15 = (double)FUN_80292b44((double)FLOAT_803e7f90,(double)FLOAT_803db414);
        param_2[0xa5] = (uint)(float)((double)(float)param_2[0xa5] * dVar15);
      }
      fVar4 = (float)((double)FLOAT_803e7e8c * dVar16);
      fVar5 = FLOAT_803e8078;
      if ((FLOAT_803e8078 <= fVar4) && (fVar5 = fVar4, FLOAT_803e807c < fVar4)) {
        fVar5 = FLOAT_803e807c;
      }
      param_2[0xa5] = (uint)(fVar5 * FLOAT_803db414 + (float)param_2[0xa5]);
      fVar4 = (float)param_2[0xa5];
      fVar5 = FLOAT_803e8080;
      if ((FLOAT_803e8080 <= fVar4) &&
         (fVar6 = FLOAT_803e7efc + *(float *)(iVar12 + 0x404), fVar5 = fVar4, fVar6 < fVar4)) {
        fVar5 = fVar6;
      }
      param_2[0xa5] = (uint)fVar5;
      dVar16 = (double)FUN_80021370((double)((float)(dVar14 * (double)FLOAT_803e7f74) -
                                            (float)param_2[0xa1]),(double)FLOAT_803e807c,
                                    (double)FLOAT_803db414);
      param_2[0xa1] = (uint)(float)((double)(float)param_2[0xa1] + dVar16);
    }
    if ((((*(byte *)(iVar12 + 0x3f0) >> 4 & 1) == 0) && ((*(byte *)(iVar12 + 0x3f1) >> 1 & 1) == 0))
       && ((*(byte *)(iVar12 + 0x3f0) >> 1 & 1) == 0)) {
      dVar16 = (double)FUN_80021370((double)((float)param_2[0xa5] - (float)param_2[0xa0]),
                                    (double)*(float *)(iVar12 + 0x82c),(double)FLOAT_803db414);
      param_2[0xa0] = (uint)(float)((double)(float)param_2[0xa0] + dVar16);
    }
    iVar8 = 0;
  }
  else {
    local_48 = (double)CONCAT44(0x43300000,*(uint *)(iVar12 + 0x474) ^ 0x80000000);
    dVar14 = (double)FUN_80293e80((double)((FLOAT_803e7f94 * (float)(local_48 - DOUBLE_803e7ec0)) /
                                          FLOAT_803e7f98));
    dVar15 = (double)(*(float *)(iVar12 + 0x404) * (float)(dVar16 * -dVar14));
    local_50 = (double)CONCAT44(0x43300000,*(uint *)(iVar12 + 0x474) ^ 0x80000000);
    dVar14 = (double)FUN_80294204((double)((FLOAT_803e7f94 * (float)(local_50 - DOUBLE_803e7ec0)) /
                                          FLOAT_803e7f98));
    dVar14 = (double)(*(float *)(iVar12 + 0x404) * (float)(dVar16 * -dVar14));
    dVar16 = (double)FUN_80021370((double)(float)(dVar15 - (double)*(float *)(iVar12 + 0x4c8)),
                                  (double)*(float *)(iVar12 + 0x438),(double)FLOAT_803db414);
    dVar14 = (double)FUN_80021370((double)(float)(dVar14 - (double)*(float *)(iVar12 + 0x4cc)),
                                  (double)*(float *)(iVar12 + 0x438),(double)FLOAT_803db414);
    *(float *)(iVar12 + 0x4c8) = (float)((double)*(float *)(iVar12 + 0x4c8) + dVar16);
    *(float *)(iVar12 + 0x4cc) = (float)((double)*(float *)(iVar12 + 0x4cc) + dVar14);
    dVar16 = (double)FUN_802931a0((double)(*(float *)(iVar12 + 0x4c8) * *(float *)(iVar12 + 0x4c8) +
                                          *(float *)(iVar12 + 0x4cc) * *(float *)(iVar12 + 0x4cc)));
    param_2[0xa5] = (uint)(float)dVar16;
    fVar4 = (float)param_2[0xa5];
    fVar5 = **(float **)(iVar12 + 0x400);
    if ((fVar5 <= fVar4) && (fVar5 = fVar4, *(float *)(iVar12 + 0x404) < fVar4)) {
      fVar5 = *(float *)(iVar12 + 0x404);
    }
    param_2[0xa5] = (uint)fVar5;
    local_48 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar12 + 0x478) ^ 0x80000000);
    dVar16 = (double)FUN_80293e80((double)((FLOAT_803e7f94 * (float)(local_48 - DOUBLE_803e7ec0)) /
                                          FLOAT_803e7f98));
    local_50 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar12 + 0x478) ^ 0x80000000);
    dVar14 = (double)FUN_80294204((double)((FLOAT_803e7f94 * (float)(local_50 - DOUBLE_803e7ec0)) /
                                          FLOAT_803e7f98));
    dVar15 = (double)(float)((double)*(float *)(iVar12 + 0x4c8) * dVar14 -
                            (double)(float)((double)*(float *)(iVar12 + 0x4cc) * dVar16));
    dVar16 = (double)FUN_80021370((double)((float)(-(double)*(float *)(iVar12 + 0x4cc) * dVar14 -
                                                  (double)(float)((double)*(float *)(iVar12 + 0x4c8)
                                                                 * dVar16)) - (float)param_2[0xa0]),
                                  (double)*(float *)(iVar12 + 0x82c),(double)FLOAT_803db414);
    param_2[0xa0] = (uint)(float)((double)(float)param_2[0xa0] + dVar16);
    dVar16 = (double)FUN_80021370((double)(float)(dVar15 - (double)(float)param_2[0xa1]),
                                  (double)*(float *)(iVar12 + 0x82c),(double)FLOAT_803db414);
    param_2[0xa1] = (uint)(float)((double)(float)param_2[0xa1] + dVar16);
    dVar16 = (double)(float)param_2[0xa1];
    if (dVar16 < (double)FLOAT_803e7ea4) {
      dVar16 = -dVar16;
    }
    dVar14 = (double)(float)param_2[0xa0];
    if (dVar14 < (double)FLOAT_803e7ea4) {
      dVar14 = -dVar14;
    }
    iVar8 = FUN_8002f5d4((double)(float)param_2[0xa5],param_1,param_2 + 0xa8);
    if (iVar8 == 0) {
      param_2[0xa8] = (uint)FLOAT_803e7f78;
    }
    if ((*(byte *)(iVar12 + 0x3f0) >> 5 & 1) != 0) {
      param_2[0xa8] = (uint)((float)param_2[0xa8] * FLOAT_803e7e98);
    }
    if (dVar14 <= dVar16) {
      if ((float)param_2[0xa1] < FLOAT_803e7ea4) {
        iVar8 = 2;
      }
      else {
        iVar8 = 3;
      }
    }
    else if (FLOAT_803e7ea4 <= (float)param_2[0xa0]) {
      iVar8 = 0;
    }
    else {
      iVar8 = 1;
    }
  }
  bVar2 = *(byte *)(iVar12 + 0x3f0);
  if (((-1 < (char)bVar2) && ((bVar2 >> 6 & 1) == 0)) &&
     (((bVar2 >> 4 & 1) == 0 &&
      ((((bVar2 >> 2 & 1) == 0 && ((bVar2 >> 3 & 1) == 0)) && ((bVar2 >> 1 & 1) == 0)))))) {
    bVar1 = (*(byte *)(iVar12 + 0x3f1) >> 3 & 1) == 0;
    fVar4 = FLOAT_803e7ea4;
    if (bVar1) {
      fVar4 = *(float *)(param_1 + 0x98);
    }
    dVar16 = (double)fVar4;
    uVar9 = (uint)*(char *)(iVar12 + 0x8cc);
    uVar9 = ((int)uVar9 >> 2) + (uint)((int)uVar9 < 0 && (uVar9 & 3) != 0);
    *(char *)(iVar12 + 0x8b0) = (char)((int)(uVar9 * 2 | uVar9 >> 0x1f) >> 1) + '\x01';
    if (4 < *(byte *)(iVar12 + 0x8b0)) {
      *(undefined *)(iVar12 + 0x8b0) = 4;
    }
    if (*(byte *)(iVar12 + 0x8b0) < 4) {
      uVar10 = *(undefined *)(iVar12 + 0x8a3);
    }
    else {
      uVar10 = *(undefined *)(iVar12 + 0x8a4);
    }
    *(undefined *)(iVar12 + 0x8a6) = uVar10;
    fVar4 = (float)param_2[0xa5];
    iVar11 = *(int *)(iVar12 + 0x400);
    if (*(float *)(iVar11 + uVar9 * 8) <= fVar4) {
      if ((*(float *)(iVar11 + uVar9 * 8 + 4) <= fVar4) && (*(char *)(iVar12 + 0x8cc) < '\x14')) {
        if (*(char *)(iVar12 + 0x8cc) == '\0') {
          dVar16 = (double)FLOAT_803e7ea4;
        }
        if (fVar4 < *(float *)(iVar12 + 0x404)) {
          *(char *)(iVar12 + 0x8cc) = *(char *)(iVar12 + 0x8cc) + '\x04';
        }
      }
    }
    else if (*(char *)(iVar12 + 0x8cc) == '\x04') {
      if (((float)param_2[0xa0] < *(float *)(iVar11 + 0x10)) &&
         ((float)param_2[0xa6] < FLOAT_803e7f14)) {
        param_2[0xc2] = (uint)FUN_802a514c;
        iVar8 = 2;
        goto LAB_802a665c;
      }
    }
    else {
      *(char *)(iVar12 + 0x8cc) = *(char *)(iVar12 + 0x8cc) + -4;
    }
    if (((((!bVar1) || (*(int *)(iVar12 + 0x3fc) != *(int *)(iVar12 + 0x3f8))) ||
         (*(short *)(param_1 + 0xa0) !=
          *(short *)(*(int *)(iVar12 + 0x3f8) + (*(char *)(iVar12 + 0x8cc) + iVar8) * 2))) &&
        ((iVar11 = FUN_8002f50c(param_1), iVar11 == 0 || ((*(byte *)(iVar12 + 0x3f2) >> 4 & 1) != 0)
         ))) && ((FUN_80030334(dVar16,param_1,
                               (int)*(short *)(*(int *)(iVar12 + 0x3f8) +
                                              (*(char *)(iVar12 + 0x8cc) + iVar8) * 2),0),
                 (*(byte *)(iVar12 + 0x3f1) >> 5 & 1) != 0 &&
                 (*(char *)((int)param_2 + 0x27a) == '\0')))) {
      FUN_8002f574(param_1,0xc);
    }
  }
  local_48 = (double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x67) ^ 0x80000000);
  dVar14 = (double)((float)(local_48 - DOUBLE_803e7ec0) / FLOAT_803e7ee8);
  dVar16 = (double)FLOAT_803e7ecc;
  if ((dVar16 <= dVar14) && (dVar16 = dVar14, (double)FLOAT_803e7ee0 < dVar14)) {
    dVar16 = (double)FLOAT_803e7ee0;
  }
  dVar14 = dVar16;
  if (dVar16 < (double)FLOAT_803e7ea4) {
    dVar14 = -dVar16;
  }
  if (((((*(byte *)(iVar12 + 0x3f1) >> 5 & 1) == 0) &&
       (bVar2 = *(byte *)(iVar12 + 0x3f0), -1 < (char)bVar2)) && ((bVar2 >> 6 & 1) == 0)) &&
     ((((bVar2 >> 4 & 1) == 0 && ((bVar2 >> 2 & 1) == 0)) &&
      (((bVar2 >> 3 & 1) == 0 && ((bVar2 >> 1 & 1) == 0)))))) {
    if ((bVar2 >> 5 & 1) == 0) {
      FUN_8002ed6c(param_1,(int)*(short *)(*(int *)(iVar12 + 0x3f8) +
                                           ((int)*(char *)(iVar12 + 0x8cc) +
                                           (uint)((double)FLOAT_803e7ea4 < dVar16)) * 2 + 2),
                   (int)((double)FLOAT_803e7fac * dVar14));
    }
    iVar8 = FUN_8002f5d4((double)(float)param_2[0xa5],param_1,param_2 + 0xa8);
    if (iVar8 == 0) {
      param_2[0xa8] = (uint)FLOAT_803e7f78;
    }
  }
  FUN_802abae8(dVar16,param_1,param_2,iVar12);
  iVar8 = 0;
LAB_802a665c:
  __psq_l0(auStack8,uVar13);
  __psq_l1(auStack8,uVar13);
  __psq_l0(auStack24,uVar13);
  __psq_l1(auStack24,uVar13);
  __psq_l0(auStack40,uVar13);
  __psq_l1(auStack40,uVar13);
  return iVar8;
}

