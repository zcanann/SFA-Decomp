// Function: FUN_802bd584
// Entry: 802bd584
// Size: 2456 bytes

/* WARNING: Removing unreachable block (ram,0x802bdef4) */
/* WARNING: Removing unreachable block (ram,0x802bd594) */

undefined4
FUN_802bd584(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  float fVar2;
  float fVar3;
  bool bVar4;
  uint uVar5;
  undefined uVar7;
  short sVar6;
  int iVar8;
  int iVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  
  iVar9 = *(int *)(param_9 + 0xb8);
  *(byte *)(iVar9 + 0xf49) = *(byte *)(iVar9 + 0xf49) & 0xfb;
  *(byte *)(iVar9 + 0xf49) = *(byte *)(iVar9 + 0xf49) & 0xf7;
  *(byte *)(iVar9 + 0xf4a) = *(byte *)(iVar9 + 0xf4a) & 0xef;
  if (*(char *)((int)param_10 + 0x27a) != '\0') {
    *(byte *)(iVar9 + 0xf48) = *(byte *)(iVar9 + 0xf48) & 0x7f;
    *(byte *)(iVar9 + 0xf48) = *(byte *)(iVar9 + 0xf48) & 0xbf;
    *(undefined *)(iVar9 + 0x1424) = 0;
    *(byte *)(iVar9 + 0xf4a) = *(byte *)(iVar9 + 0xf4a) & 0xef | 0x10;
  }
  if ((((-1 < (char)*(byte *)(iVar9 + 0xf48)) && ((*(byte *)(iVar9 + 0xf48) >> 6 & 1) == 0)) &&
      ((*(byte *)(iVar9 + 0x14ec) & 1) == 0)) && ((param_10[199] & 0x100) != 0)) {
    FUN_80014b68(0,0x100);
    *(byte *)(iVar9 + 0x14ec) = *(byte *)(iVar9 + 0x14ec) & 0xfe | 1;
    *(undefined *)(*(int *)(param_9 + 0x54) + 0x70) = 0;
    FUN_8003042c((double)FLOAT_803e8f9c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0x14,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)((int)param_10 + 0x346) = 0;
    FUN_8000bb38(param_9,0x121);
  }
  *param_10 = *param_10 | 0x800000;
  *(undefined2 *)(param_10 + 0x9e) = 0;
  *(float *)(iVar9 + 0xf5c) = FLOAT_803e8f80;
  if (*(char *)((int)param_10 + 0x27a) != '\0') {
    *(short *)(iVar9 + 0xfdc) =
         *(short *)(iVar9 + 0xfdc) + (short)*(undefined4 *)(iVar9 + 0xfe4) * 0xb6;
    *(undefined4 *)(iVar9 + 0xfe0) = 0;
    *(undefined4 *)(iVar9 + 0xfe4) = 0;
  }
  dVar12 = (double)(((float)param_10[0xa6] - FLOAT_803e8fa0) / FLOAT_803e8f94);
  dVar11 = (double)(*(float *)(iVar9 + 0xf5c) - FLOAT_803e8fd4);
  dVar10 = (double)FLOAT_803e8f9c;
  if ((dVar10 <= dVar12) && (dVar10 = dVar12, (double)FLOAT_803e8fd0 < dVar12)) {
    dVar10 = (double)FLOAT_803e8fd0;
  }
  *(float *)(iVar9 + 0xf60) =
       (float)(dVar11 * (double)(float)(dVar10 * (double)*(float *)(iVar9 + 0x1398)));
  if ((*(byte *)(iVar9 + 0xf48) >> 6 & 1) == 0) {
    if ((char)*(byte *)(iVar9 + 0xf48) < '\0') {
      iVar8 = FUN_802bcfa0(dVar10,dVar11,dVar12,param_4,param_5,param_6,param_7,param_8,param_9,
                           iVar9 + 0xb58,(int)param_10,param_12,param_13,param_14,param_15,param_16)
      ;
      if (iVar8 != 0) {
        return 2;
      }
    }
    else if ((*(byte *)(iVar9 + 0x14ec) & 1) != 0) {
      param_10[0xa8] = (uint)FLOAT_803e8fa8;
      if (*(char *)((int)param_10 + 0x346) != '\0') {
        *(byte *)(iVar9 + 0x14ec) = *(byte *)(iVar9 + 0x14ec) & 0xfe;
        *(byte *)(iVar9 + 0xf49) = *(byte *)(iVar9 + 0xf49) & 0xf7 | 8;
        *(undefined *)(*(int *)(param_9 + 0x54) + 0x70) = 0;
      }
      fVar1 = FLOAT_803e8fac;
      *(float *)(iVar9 + 0xf80) = *(float *)(iVar9 + 0xf80) * FLOAT_803e8fac;
      fVar2 = FLOAT_803e8fb0;
      *(float *)(iVar9 + 0xf84) = *(float *)(iVar9 + 0xf84) * FLOAT_803e8fb0;
      *(float *)(iVar9 + 0xf88) = *(float *)(iVar9 + 0xf88) * fVar1;
      *(float *)(iVar9 + 0xf8c) = *(float *)(iVar9 + 0xf8c) * fVar2;
      *(float *)(iVar9 + 0xf60) = *(float *)(iVar9 + 0xf60) * FLOAT_803e8fb4;
      fVar1 = *(float *)(*(int *)(iVar9 + 0xf58) + 0xc);
      if (*(float *)(iVar9 + 0xf60) < fVar1) {
        *(float *)(iVar9 + 0xf60) = fVar1;
      }
      *(undefined *)(*(int *)(param_9 + 0x54) + 0x6e) = 0x15;
      *(undefined *)(*(int *)(param_9 + 0x54) + 0x6f) = 2;
    }
  }
  else {
    *(uint *)(iVar9 + 0xeb8) = *(uint *)(iVar9 + 0xeb8) | 0x1000000;
    param_10[0xa8] = (uint)FLOAT_803e8f98;
    dVar12 = (double)FLOAT_803e8fb8;
    local_38 = (double)CONCAT44(0x43300000,*(uint *)(iVar9 + 0x13b0) ^ 0x80000000);
    sVar6 = (short)(int)(dVar12 * (double)*(float *)(param_9 + 0x98) +
                        (double)(float)(local_38 - DOUBLE_803e8f78));
    *(short *)(iVar9 + 0xfd0) = sVar6;
    *(int *)(iVar9 + 0xfec) = (int)sVar6;
    if (*(char *)((int)param_10 + 0x346) != '\0') {
      *(byte *)(iVar9 + 0xf48) = *(byte *)(iVar9 + 0xf48) & 0xbf;
      *(short *)(iVar9 + 0xfd0) = *(short *)(iVar9 + 0xfdc);
      *(int *)(iVar9 + 0xfec) = (int)*(short *)(iVar9 + 0xfdc);
      *(undefined *)(iVar9 + 0x1424) = 0xc;
      *(byte *)(iVar9 + 0xf49) = *(byte *)(iVar9 + 0xf49) & 0xfb | 4;
      *(byte *)(iVar9 + 0xf49) = *(byte *)(iVar9 + 0xf49) & 0xf7 | 8;
    }
    param_10[0xa5] = (uint)(*(float *)(iVar9 + 0x139c) * FLOAT_803dc074 + (float)param_10[0xa5]);
    *(float *)(iVar9 + 0xf60) = FLOAT_803e8f9c;
    if ((FLOAT_803e8f88 < *(float *)(param_9 + 0x98)) &&
       (*(float *)(param_9 + 0x98) < FLOAT_803e8fb0)) {
      *(ushort *)(iVar9 + 0x1430) = *(ushort *)(iVar9 + 0x1430) | 8;
    }
  }
  if (((((*(byte *)(iVar9 + 0x14ec) & 1) == 0) && ((*(byte *)(iVar9 + 0xf48) >> 6 & 1) == 0)) &&
      (-1 < (char)*(byte *)(iVar9 + 0xf48))) &&
     ((fVar1 = (float)param_10[0xa5],
      (double)(FLOAT_803e8fd8 + *(float *)(*(int *)(iVar9 + 0xf58) + 0x14)) < (double)fVar1 &&
      ((*(float *)(iVar9 + 0xfc8) < FLOAT_803e8fdc || (0x95 < *(int *)(iVar9 + 0xfe0))))))) {
    *(byte *)(iVar9 + 0xf48) = *(byte *)(iVar9 + 0xf48) & 0x7f | 0x80;
    *(uint *)(iVar9 + 0xeb8) = *(uint *)(iVar9 + 0xeb8) | 0x1000000;
    *(uint *)(iVar9 + 0x139c) = param_10[0xa0];
    FUN_8003042c((double)FLOAT_803e8f9c,(double)fVar1,dVar12,param_4,param_5,param_6,param_7,param_8
                 ,param_9,(int)*(short *)(*(int *)(iVar9 + 0xf50) + 0x3c),0,param_12,param_13,
                 param_14,param_15,param_16);
    param_10[0xa8] = (uint)FLOAT_803e8f84;
  }
  if ((-1 < (char)*(byte *)(iVar9 + 0xf48)) && ((*(byte *)(iVar9 + 0xf48) >> 6 & 1) == 0)) {
    if (*(int *)(iVar9 + 0xfe0) < 0x96) {
      local_30 = (double)CONCAT44(0x43300000,*(uint *)(iVar9 + 0xfd4) ^ 0x80000000);
      dVar10 = FUN_80021434((double)(float)(local_30 - DOUBLE_803e8f78),
                            (double)(FLOAT_803e8fd0 / *(float *)(iVar9 + 0xf80)),
                            (double)FLOAT_803dc074);
      dVar11 = (double)(FLOAT_803dc074 * *(float *)(iVar9 + 0xf84) * *(float *)(iVar9 + 0xf78));
      if (dVar11 < dVar10) {
        dVar10 = dVar11;
      }
      if (*(int *)(iVar9 + 0xfd8) < 0) {
        dVar10 = -dVar10;
      }
      local_38 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar9 + 0xfd0) ^ 0x80000000);
      *(short *)(iVar9 + 0xfd0) =
           (short)(int)((double)FLOAT_803e8fe0 * dVar10 +
                       (double)(float)(local_38 - DOUBLE_803e8f78));
    }
    if ((int)*(uint *)(iVar9 + 0xfe0) < 0x96) {
      local_28 = (double)CONCAT44(0x43300000,*(uint *)(iVar9 + 0xfe0) ^ 0x80000000);
      dVar10 = FUN_80021434((double)(float)(local_28 - DOUBLE_803e8f78),
                            (double)(FLOAT_803e8fd0 / *(float *)(iVar9 + 0xf88)),
                            (double)FLOAT_803dc074);
      dVar11 = (double)(*(float *)(iVar9 + 0xf8c) * FLOAT_803dc074);
      if (dVar11 < dVar10) {
        dVar10 = dVar11;
      }
      if (*(int *)(iVar9 + 0xfe4) < 0) {
        dVar10 = -dVar10;
      }
      local_30 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar9 + 0xfdc) ^ 0x80000000);
      *(short *)(iVar9 + 0xfdc) =
           (short)(int)((double)FLOAT_803e8fe0 * dVar10 +
                       (double)(float)(local_30 - DOUBLE_803e8f78));
    }
    else if (((float)param_10[0xa5] <= *(float *)(*(int *)(iVar9 + 0xf58) + 4)) &&
            ((float)param_10[0xa0] <= *(float *)(*(int *)(iVar9 + 0xf58) + 0xc))) {
      *(short *)(iVar9 + 0xfdc) =
           *(short *)(iVar9 + 0xfdc) + (short)*(undefined4 *)(iVar9 + 0xfe4) * 0xb6;
    }
  }
  if (((*(byte *)(iVar9 + 0xf48) >> 6 & 1) == 0) && ((*(byte *)(iVar9 + 0xf49) >> 2 & 1) == 0)) {
    dVar11 = FUN_80021434((double)(*(float *)(iVar9 + 0xf60) - (float)param_10[0xa5]),
                          (double)*(float *)(iVar9 + 0xf90),(double)FLOAT_803dc074);
    dVar10 = (double)(FLOAT_803e8fe4 * FLOAT_803dc074);
    if ((dVar10 <= dVar11) && (dVar10 = dVar11, (double)(FLOAT_803e8f88 * FLOAT_803dc074) < dVar11))
    {
      dVar10 = (double)(FLOAT_803e8f88 * FLOAT_803dc074);
    }
    if ((0x95 < *(int *)(iVar9 + 0xfe0)) && ((double)FLOAT_803e8f9c < dVar10)) {
      dVar10 = (double)(float)((double)FLOAT_803e8fac * -dVar10);
    }
    param_10[0xa5] = (uint)(float)((double)(float)param_10[0xa5] + dVar10);
    fVar1 = (float)param_10[0xa5];
    fVar2 = **(float **)(iVar9 + 0xf58);
    if ((fVar2 <= fVar1) && (fVar2 = fVar1, *(float *)(iVar9 + 0xf5c) < fVar1)) {
      fVar2 = *(float *)(iVar9 + 0xf5c);
    }
    param_10[0xa5] = (uint)fVar2;
    param_10[0xa1] = (uint)FLOAT_803e8f9c;
  }
  else {
    fVar1 = (float)param_10[0xa5];
    fVar2 = *(float *)(iVar9 + 0xf5c);
    fVar3 = -fVar2;
    if ((fVar3 <= fVar1) && (fVar3 = fVar1, fVar2 < fVar1)) {
      fVar3 = fVar2;
    }
    param_10[0xa5] = (uint)fVar3;
  }
  dVar11 = (double)*(float *)(iVar9 + 0x1384);
  dVar12 = (double)FLOAT_803dc074;
  dVar10 = FUN_80021434((double)((float)param_10[0xa5] - (float)param_10[0xa0]),dVar11,dVar12);
  param_10[0xa0] = (uint)(float)((double)(float)param_10[0xa0] + dVar10);
  if (((-1 < (char)*(byte *)(iVar9 + 0xf48)) && ((*(byte *)(iVar9 + 0xf48) >> 6 & 1) == 0)) &&
     ((*(byte *)(iVar9 + 0x14ec) & 1) == 0)) {
    bVar4 = (*(byte *)(iVar9 + 0xf49) >> 3 & 1) == 0;
    fVar1 = FLOAT_803e8f9c;
    if (bVar4) {
      fVar1 = *(float *)(param_9 + 0x98);
    }
    dVar10 = (double)fVar1;
    uVar5 = (uint)*(char *)(iVar9 + 0x1424);
    uVar5 = ((int)uVar5 >> 2) + (uint)((int)uVar5 < 0 && (uVar5 & 3) != 0);
    *(char *)(iVar9 + 0x1408) = (char)((int)(uVar5 * 2 | uVar5 >> 0x1f) >> 1) + '\x01';
    if (4 < *(byte *)(iVar9 + 0x1408)) {
      *(undefined *)(iVar9 + 0x1408) = 4;
    }
    if (*(byte *)(iVar9 + 0x1408) < 4) {
      uVar7 = 8;
    }
    else {
      uVar7 = 10;
    }
    *(undefined *)(iVar9 + 0x13fe) = uVar7;
    fVar1 = (float)param_10[0xa5];
    iVar8 = *(int *)(iVar9 + 0xf58);
    if (*(float *)(iVar8 + uVar5 * 8) <= fVar1) {
      if ((*(float *)(iVar8 + uVar5 * 8 + 4) <= fVar1) && (*(char *)(iVar9 + 0x1424) < '\x14')) {
        if (*(char *)(iVar9 + 0x1424) == '\0') {
          dVar10 = (double)FLOAT_803e8fe8;
        }
        if (fVar1 < *(float *)(iVar9 + 0xf5c)) {
          *(char *)(iVar9 + 0x1424) = *(char *)(iVar9 + 0x1424) + '\x04';
        }
      }
    }
    else if (*(char *)(iVar9 + 0x1424) == '\x04') {
      if (((float)param_10[0xa0] < *(float *)(iVar8 + 0x10)) &&
         ((float)param_10[0xa6] < FLOAT_803e8fa0)) {
        return 2;
      }
    }
    else {
      *(char *)(iVar9 + 0x1424) = *(char *)(iVar9 + 0x1424) + -4;
    }
    if ((((!bVar4) || (*(int *)(iVar9 + 0xf54) != *(int *)(iVar9 + 0xf50))) ||
        (*(short *)(param_9 + 0xa0) !=
         *(short *)(*(int *)(iVar9 + 0xf50) + *(char *)(iVar9 + 0x1424) * 2))) &&
       ((sVar6 = FUN_8002f604(param_9), sVar6 == 0 || ((*(byte *)(iVar9 + 0xf4a) >> 4 & 1) != 0))))
    {
      if (*(short *)(param_9 + 0xa0) == 0x14) {
        dVar10 = (double)FLOAT_803e8fe8;
      }
      FUN_8003042c(dVar10,dVar11,dVar12,param_4,param_5,param_6,param_7,param_8,param_9,
                   (int)*(short *)(*(int *)(iVar9 + 0xf50) + *(char *)(iVar9 + 0x1424) * 2),0,
                   param_12,param_13,param_14,param_15,param_16);
    }
  }
  if (((-1 < (char)*(byte *)(iVar9 + 0xf48)) && ((*(byte *)(iVar9 + 0xf48) >> 6 & 1) == 0)) &&
     (((*(byte *)(iVar9 + 0x14ec) & 1) == 0 &&
      (iVar8 = FUN_8002f6cc((double)(float)param_10[0xa5],param_9,(float *)(param_10 + 0xa8)),
      iVar8 == 0)))) {
    param_10[0xa8] = (uint)FLOAT_803e8fec;
  }
  FUN_802bd180(param_9,iVar9 + 0xb58,(int)param_10);
  return 0;
}

