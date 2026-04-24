// Function: FUN_802bce14
// Entry: 802bce14
// Size: 2456 bytes

/* WARNING: Removing unreachable block (ram,0x802bd784) */

undefined4 FUN_802bce14(int param_1,uint *param_2)

{
  bool bVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  short sVar5;
  uint uVar6;
  undefined uVar8;
  undefined4 uVar7;
  int iVar9;
  int iVar10;
  undefined4 uVar11;
  double dVar12;
  double dVar13;
  undefined8 in_f31;
  double local_38;
  double local_30;
  double local_28;
  undefined auStack8 [8];
  
  uVar11 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar10 = *(int *)(param_1 + 0xb8);
  *(byte *)(iVar10 + 0xf49) = *(byte *)(iVar10 + 0xf49) & 0xfb;
  *(byte *)(iVar10 + 0xf49) = *(byte *)(iVar10 + 0xf49) & 0xf7;
  *(byte *)(iVar10 + 0xf4a) = *(byte *)(iVar10 + 0xf4a) & 0xef;
  if (*(char *)((int)param_2 + 0x27a) != '\0') {
    *(byte *)(iVar10 + 0xf48) = *(byte *)(iVar10 + 0xf48) & 0x7f;
    *(byte *)(iVar10 + 0xf48) = *(byte *)(iVar10 + 0xf48) & 0xbf;
    *(undefined *)(iVar10 + 0x1424) = 0;
    *(byte *)(iVar10 + 0xf4a) = *(byte *)(iVar10 + 0xf4a) & 0xef | 0x10;
  }
  if ((((-1 < (char)*(byte *)(iVar10 + 0xf48)) && ((*(byte *)(iVar10 + 0xf48) >> 6 & 1) == 0)) &&
      ((*(byte *)(iVar10 + 0x14ec) & 1) == 0)) && ((param_2[199] & 0x100) != 0)) {
    FUN_80014b3c(0,0x100);
    *(byte *)(iVar10 + 0x14ec) = *(byte *)(iVar10 + 0x14ec) & 0xfe | 1;
    *(undefined *)(*(int *)(param_1 + 0x54) + 0x70) = 0;
    FUN_80030334((double)FLOAT_803e8304,param_1,0x14,0);
    *(undefined *)((int)param_2 + 0x346) = 0;
    FUN_8000bb18(param_1,0x121);
  }
  *param_2 = *param_2 | 0x800000;
  *(undefined2 *)(param_2 + 0x9e) = 0;
  *(float *)(iVar10 + 0xf5c) = FLOAT_803e82e8;
  if (*(char *)((int)param_2 + 0x27a) != '\0') {
    *(short *)(iVar10 + 0xfdc) =
         *(short *)(iVar10 + 0xfdc) + (short)*(undefined4 *)(iVar10 + 0xfe4) * 0xb6;
    *(undefined4 *)(iVar10 + 0xfe0) = 0;
    *(undefined4 *)(iVar10 + 0xfe4) = 0;
  }
  fVar2 = ((float)param_2[0xa6] - FLOAT_803e8308) / FLOAT_803e82fc;
  fVar3 = FLOAT_803e8304;
  if ((FLOAT_803e8304 <= fVar2) && (fVar3 = fVar2, FLOAT_803e8338 < fVar2)) {
    fVar3 = FLOAT_803e8338;
  }
  *(float *)(iVar10 + 0xf60) =
       (*(float *)(iVar10 + 0xf5c) - FLOAT_803e833c) * fVar3 * *(float *)(iVar10 + 0x1398);
  if ((*(byte *)(iVar10 + 0xf48) >> 6 & 1) == 0) {
    if ((char)*(byte *)(iVar10 + 0xf48) < '\0') {
      iVar9 = FUN_802bc830(param_1,iVar10 + 0xb58,param_2);
      if (iVar9 != 0) {
        uVar7 = 2;
        goto LAB_802bd784;
      }
    }
    else if ((*(byte *)(iVar10 + 0x14ec) & 1) != 0) {
      param_2[0xa8] = (uint)FLOAT_803e8310;
      if (*(char *)((int)param_2 + 0x346) != '\0') {
        *(byte *)(iVar10 + 0x14ec) = *(byte *)(iVar10 + 0x14ec) & 0xfe;
        *(byte *)(iVar10 + 0xf49) = *(byte *)(iVar10 + 0xf49) & 0xf7 | 8;
        *(undefined *)(*(int *)(param_1 + 0x54) + 0x70) = 0;
      }
      fVar2 = FLOAT_803e8314;
      *(float *)(iVar10 + 0xf80) = *(float *)(iVar10 + 0xf80) * FLOAT_803e8314;
      fVar3 = FLOAT_803e8318;
      *(float *)(iVar10 + 0xf84) = *(float *)(iVar10 + 0xf84) * FLOAT_803e8318;
      *(float *)(iVar10 + 0xf88) = *(float *)(iVar10 + 0xf88) * fVar2;
      *(float *)(iVar10 + 0xf8c) = *(float *)(iVar10 + 0xf8c) * fVar3;
      *(float *)(iVar10 + 0xf60) = *(float *)(iVar10 + 0xf60) * FLOAT_803e831c;
      fVar2 = *(float *)(*(int *)(iVar10 + 0xf58) + 0xc);
      if (*(float *)(iVar10 + 0xf60) < fVar2) {
        *(float *)(iVar10 + 0xf60) = fVar2;
      }
      *(undefined *)(*(int *)(param_1 + 0x54) + 0x6e) = 0x15;
      *(undefined *)(*(int *)(param_1 + 0x54) + 0x6f) = 2;
    }
  }
  else {
    *(uint *)(iVar10 + 0xeb8) = *(uint *)(iVar10 + 0xeb8) | 0x1000000;
    param_2[0xa8] = (uint)FLOAT_803e8300;
    local_38 = (double)CONCAT44(0x43300000,*(uint *)(iVar10 + 0x13b0) ^ 0x80000000);
    sVar5 = (short)(int)(FLOAT_803e8320 * *(float *)(param_1 + 0x98) +
                        (float)(local_38 - DOUBLE_803e82e0));
    *(short *)(iVar10 + 0xfd0) = sVar5;
    *(int *)(iVar10 + 0xfec) = (int)sVar5;
    if (*(char *)((int)param_2 + 0x346) != '\0') {
      *(byte *)(iVar10 + 0xf48) = *(byte *)(iVar10 + 0xf48) & 0xbf;
      *(short *)(iVar10 + 0xfd0) = *(short *)(iVar10 + 0xfdc);
      *(int *)(iVar10 + 0xfec) = (int)*(short *)(iVar10 + 0xfdc);
      *(undefined *)(iVar10 + 0x1424) = 0xc;
      *(byte *)(iVar10 + 0xf49) = *(byte *)(iVar10 + 0xf49) & 0xfb | 4;
      *(byte *)(iVar10 + 0xf49) = *(byte *)(iVar10 + 0xf49) & 0xf7 | 8;
    }
    param_2[0xa5] = (uint)(*(float *)(iVar10 + 0x139c) * FLOAT_803db414 + (float)param_2[0xa5]);
    *(float *)(iVar10 + 0xf60) = FLOAT_803e8304;
    if ((FLOAT_803e82f0 < *(float *)(param_1 + 0x98)) &&
       (*(float *)(param_1 + 0x98) < FLOAT_803e8318)) {
      *(ushort *)(iVar10 + 0x1430) = *(ushort *)(iVar10 + 0x1430) | 8;
    }
  }
  if (((((*(byte *)(iVar10 + 0x14ec) & 1) == 0) && ((*(byte *)(iVar10 + 0xf48) >> 6 & 1) == 0)) &&
      (-1 < (char)*(byte *)(iVar10 + 0xf48))) &&
     ((FLOAT_803e8340 + *(float *)(*(int *)(iVar10 + 0xf58) + 0x14) < (float)param_2[0xa5] &&
      ((*(float *)(iVar10 + 0xfc8) < FLOAT_803e8344 || (0x95 < *(int *)(iVar10 + 0xfe0))))))) {
    *(byte *)(iVar10 + 0xf48) = *(byte *)(iVar10 + 0xf48) & 0x7f | 0x80;
    *(uint *)(iVar10 + 0xeb8) = *(uint *)(iVar10 + 0xeb8) | 0x1000000;
    *(uint *)(iVar10 + 0x139c) = param_2[0xa0];
    FUN_80030334((double)FLOAT_803e8304,param_1,(int)*(short *)(*(int *)(iVar10 + 0xf50) + 0x3c),0);
    param_2[0xa8] = (uint)FLOAT_803e82ec;
  }
  if ((-1 < (char)*(byte *)(iVar10 + 0xf48)) && ((*(byte *)(iVar10 + 0xf48) >> 6 & 1) == 0)) {
    if (*(int *)(iVar10 + 0xfe0) < 0x96) {
      local_30 = (double)CONCAT44(0x43300000,*(uint *)(iVar10 + 0xfd4) ^ 0x80000000);
      dVar13 = (double)FUN_80021370((double)(float)(local_30 - DOUBLE_803e82e0),
                                    (double)(FLOAT_803e8338 / *(float *)(iVar10 + 0xf80)),
                                    (double)FLOAT_803db414);
      dVar12 = (double)(FLOAT_803db414 * *(float *)(iVar10 + 0xf84) * *(float *)(iVar10 + 0xf78));
      if (dVar12 < dVar13) {
        dVar13 = dVar12;
      }
      if (*(int *)(iVar10 + 0xfd8) < 0) {
        dVar13 = -dVar13;
      }
      local_38 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar10 + 0xfd0) ^ 0x80000000);
      *(short *)(iVar10 + 0xfd0) =
           (short)(int)((double)FLOAT_803e8348 * dVar13 +
                       (double)(float)(local_38 - DOUBLE_803e82e0));
    }
    if ((int)*(uint *)(iVar10 + 0xfe0) < 0x96) {
      local_28 = (double)CONCAT44(0x43300000,*(uint *)(iVar10 + 0xfe0) ^ 0x80000000);
      dVar13 = (double)FUN_80021370((double)(float)(local_28 - DOUBLE_803e82e0),
                                    (double)(FLOAT_803e8338 / *(float *)(iVar10 + 0xf88)),
                                    (double)FLOAT_803db414);
      dVar12 = (double)(*(float *)(iVar10 + 0xf8c) * FLOAT_803db414);
      if (dVar12 < dVar13) {
        dVar13 = dVar12;
      }
      if (*(int *)(iVar10 + 0xfe4) < 0) {
        dVar13 = -dVar13;
      }
      local_30 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar10 + 0xfdc) ^ 0x80000000);
      *(short *)(iVar10 + 0xfdc) =
           (short)(int)((double)FLOAT_803e8348 * dVar13 +
                       (double)(float)(local_30 - DOUBLE_803e82e0));
    }
    else if (((float)param_2[0xa5] <= *(float *)(*(int *)(iVar10 + 0xf58) + 4)) &&
            ((float)param_2[0xa0] <= *(float *)(*(int *)(iVar10 + 0xf58) + 0xc))) {
      *(short *)(iVar10 + 0xfdc) =
           *(short *)(iVar10 + 0xfdc) + (short)*(undefined4 *)(iVar10 + 0xfe4) * 0xb6;
    }
  }
  if (((*(byte *)(iVar10 + 0xf48) >> 6 & 1) == 0) && ((*(byte *)(iVar10 + 0xf49) >> 2 & 1) == 0)) {
    dVar12 = (double)FUN_80021370((double)(*(float *)(iVar10 + 0xf60) - (float)param_2[0xa5]),
                                  (double)*(float *)(iVar10 + 0xf90),(double)FLOAT_803db414);
    dVar13 = (double)(FLOAT_803e834c * FLOAT_803db414);
    if ((dVar13 <= dVar12) && (dVar13 = dVar12, (double)(FLOAT_803e82f0 * FLOAT_803db414) < dVar12))
    {
      dVar13 = (double)(FLOAT_803e82f0 * FLOAT_803db414);
    }
    if ((0x95 < *(int *)(iVar10 + 0xfe0)) && ((double)FLOAT_803e8304 < dVar13)) {
      dVar13 = (double)(float)((double)FLOAT_803e8314 * -dVar13);
    }
    param_2[0xa5] = (uint)(float)((double)(float)param_2[0xa5] + dVar13);
    fVar2 = (float)param_2[0xa5];
    fVar3 = **(float **)(iVar10 + 0xf58);
    if ((fVar3 <= fVar2) && (fVar3 = fVar2, *(float *)(iVar10 + 0xf5c) < fVar2)) {
      fVar3 = *(float *)(iVar10 + 0xf5c);
    }
    param_2[0xa5] = (uint)fVar3;
    param_2[0xa1] = (uint)FLOAT_803e8304;
  }
  else {
    fVar2 = (float)param_2[0xa5];
    fVar3 = *(float *)(iVar10 + 0xf5c);
    fVar4 = -fVar3;
    if ((fVar4 <= fVar2) && (fVar4 = fVar2, fVar3 < fVar2)) {
      fVar4 = fVar3;
    }
    param_2[0xa5] = (uint)fVar4;
  }
  dVar13 = (double)FUN_80021370((double)((float)param_2[0xa5] - (float)param_2[0xa0]),
                                (double)*(float *)(iVar10 + 0x1384),(double)FLOAT_803db414);
  param_2[0xa0] = (uint)(float)((double)(float)param_2[0xa0] + dVar13);
  if (((-1 < (char)*(byte *)(iVar10 + 0xf48)) && ((*(byte *)(iVar10 + 0xf48) >> 6 & 1) == 0)) &&
     ((*(byte *)(iVar10 + 0x14ec) & 1) == 0)) {
    bVar1 = (*(byte *)(iVar10 + 0xf49) >> 3 & 1) == 0;
    fVar2 = FLOAT_803e8304;
    if (bVar1) {
      fVar2 = *(float *)(param_1 + 0x98);
    }
    dVar13 = (double)fVar2;
    uVar6 = (uint)*(char *)(iVar10 + 0x1424);
    uVar6 = ((int)uVar6 >> 2) + (uint)((int)uVar6 < 0 && (uVar6 & 3) != 0);
    *(char *)(iVar10 + 0x1408) = (char)((int)(uVar6 * 2 | uVar6 >> 0x1f) >> 1) + '\x01';
    if (4 < *(byte *)(iVar10 + 0x1408)) {
      *(undefined *)(iVar10 + 0x1408) = 4;
    }
    if (*(byte *)(iVar10 + 0x1408) < 4) {
      uVar8 = 8;
    }
    else {
      uVar8 = 10;
    }
    *(undefined *)(iVar10 + 0x13fe) = uVar8;
    fVar2 = (float)param_2[0xa5];
    iVar9 = *(int *)(iVar10 + 0xf58);
    if (*(float *)(iVar9 + uVar6 * 8) <= fVar2) {
      if ((*(float *)(iVar9 + uVar6 * 8 + 4) <= fVar2) && (*(char *)(iVar10 + 0x1424) < '\x14')) {
        if (*(char *)(iVar10 + 0x1424) == '\0') {
          dVar13 = (double)FLOAT_803e8350;
        }
        if (fVar2 < *(float *)(iVar10 + 0xf5c)) {
          *(char *)(iVar10 + 0x1424) = *(char *)(iVar10 + 0x1424) + '\x04';
        }
      }
    }
    else if (*(char *)(iVar10 + 0x1424) == '\x04') {
      if (((float)param_2[0xa0] < *(float *)(iVar9 + 0x10)) &&
         ((float)param_2[0xa6] < FLOAT_803e8308)) {
        uVar7 = 2;
        goto LAB_802bd784;
      }
    }
    else {
      *(char *)(iVar10 + 0x1424) = *(char *)(iVar10 + 0x1424) + -4;
    }
    if ((((!bVar1) || (*(int *)(iVar10 + 0xf54) != *(int *)(iVar10 + 0xf50))) ||
        (*(short *)(param_1 + 0xa0) !=
         *(short *)(*(int *)(iVar10 + 0xf50) + *(char *)(iVar10 + 0x1424) * 2))) &&
       ((iVar9 = FUN_8002f50c(param_1), iVar9 == 0 || ((*(byte *)(iVar10 + 0xf4a) >> 4 & 1) != 0))))
    {
      if (*(short *)(param_1 + 0xa0) == 0x14) {
        dVar13 = (double)FLOAT_803e8350;
      }
      FUN_80030334(dVar13,param_1,
                   (int)*(short *)(*(int *)(iVar10 + 0xf50) + *(char *)(iVar10 + 0x1424) * 2),0);
    }
  }
  if (((-1 < (char)*(byte *)(iVar10 + 0xf48)) && ((*(byte *)(iVar10 + 0xf48) >> 6 & 1) == 0)) &&
     (((*(byte *)(iVar10 + 0x14ec) & 1) == 0 &&
      (iVar9 = FUN_8002f5d4((double)(float)param_2[0xa5],param_1,param_2 + 0xa8), iVar9 == 0)))) {
    param_2[0xa8] = (uint)FLOAT_803e8354;
  }
  FUN_802bca10(param_1,iVar10 + 0xb58,param_2);
  uVar7 = 0;
LAB_802bd784:
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  return uVar7;
}

