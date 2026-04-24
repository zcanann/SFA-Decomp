// Function: FUN_802a5ae4
// Entry: 802a5ae4
// Size: 4880 bytes

/* WARNING: Removing unreachable block (ram,0x802a6dcc) */
/* WARNING: Removing unreachable block (ram,0x802a6dc4) */
/* WARNING: Removing unreachable block (ram,0x802a6dbc) */
/* WARNING: Removing unreachable block (ram,0x802a5b04) */
/* WARNING: Removing unreachable block (ram,0x802a5afc) */
/* WARNING: Removing unreachable block (ram,0x802a5af4) */

int FUN_802a5ae4(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5,
                undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9,
                uint *param_10,undefined4 param_11,float *param_12,undefined4 *param_13,
                undefined4 param_14,undefined4 param_15,int param_16)

{
  byte bVar1;
  byte bVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  bool bVar6;
  int iVar7;
  ushort uVar9;
  uint uVar8;
  undefined uVar11;
  short sVar10;
  int iVar12;
  int iVar13;
  double dVar14;
  double dVar15;
  double dVar16;
  double dVar17;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  
  iVar13 = *(int *)(param_9 + 0x5c);
  *(byte *)(iVar13 + 0x3f1) = *(byte *)(iVar13 + 0x3f1) & 0xfd;
  *(byte *)(iVar13 + 0x3f1) = *(byte *)(iVar13 + 0x3f1) & 0xfb;
  *(byte *)(iVar13 + 0x3f1) = *(byte *)(iVar13 + 0x3f1) & 0xf7;
  *(byte *)(iVar13 + 0x3f2) = *(byte *)(iVar13 + 0x3f2) & 0xef;
  if (*(char *)((int)param_10 + 0x27a) != '\0') {
    *(uint *)(iVar13 + 0x360) = *(uint *)(iVar13 + 0x360) | 0x2000000;
    *(byte *)(iVar13 + 0x3f0) = *(byte *)(iVar13 + 0x3f0) & 0x7f;
    *(byte *)(iVar13 + 0x3f0) = *(byte *)(iVar13 + 0x3f0) & 0xbf;
    *(byte *)(iVar13 + 0x3f3) = *(byte *)(iVar13 + 0x3f3) & 0xbf;
    *(undefined *)(iVar13 + 0x8cc) = 0;
    *(undefined2 *)(iVar13 + 0x81e) = 0;
    *(byte *)(iVar13 + 0x3f2) = *(byte *)(iVar13 + 0x3f2) & 0xef | 0x10;
  }
  iVar7 = FUN_802acf3c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                       (int)param_10,iVar13,param_12,param_13,param_14,param_15,param_16);
  if (iVar7 != 0) {
    return iVar7;
  }
  FUN_802ad964(param_9,iVar13);
  bVar1 = *(byte *)(iVar13 + 0x3f0);
  if ((bVar1 >> 5 & 1) == 0) {
    if ((*(byte *)(iVar13 + 0x3f1) >> 5 & 1) == 0) {
      if (((bVar1 >> 3 & 1) == 0) && ((bVar1 >> 2 & 1) == 0)) {
        *(uint *)(iVar13 + 0x360) = *(uint *)(iVar13 + 0x360) | 0x2000000;
        *param_10 = *param_10 | 0x800000;
        *(undefined2 *)(param_10 + 0x9e) = 0;
        *(float *)(iVar13 + 0x404) = FLOAT_803e8d04;
      }
      else {
        *param_10 = *param_10 | 0x200000;
        *(uint *)(iVar13 + 0x360) = *(uint *)(iVar13 + 0x360) | 0x2000000;
        *(float *)(iVar13 + 0x404) = FLOAT_803e8d00;
      }
    }
    else {
      *(uint *)(iVar13 + 0x360) = *(uint *)(iVar13 + 0x360) | 0x2000000;
      *param_10 = *param_10 | 0x800000;
      *(undefined2 *)(param_10 + 0x9e) = 0;
      *(float *)(iVar13 + 0x404) = FLOAT_803e8b6c;
    }
  }
  else {
    *param_10 = *param_10 | 0x200000;
    *(uint *)(iVar13 + 0x360) = *(uint *)(iVar13 + 0x360) | 0x2000;
    *(uint *)(iVar13 + 0x360) = *(uint *)(iVar13 + 0x360) | 0x2000000;
    *(undefined2 *)(param_10 + 0x9e) = 2;
    *(code **)(iVar13 + 0x898) = FUN_802a58ac;
    if ((*(byte *)(iVar13 + 0x3f1) >> 5 & 1) == 0) {
      *(float *)(iVar13 + 0x404) = FLOAT_803e8cfc;
    }
    else {
      *(float *)(iVar13 + 0x404) = FLOAT_803e8bc4;
    }
  }
  if (*(char *)((int)param_10 + 0x27a) != '\0') {
    if (((*(byte *)(iVar13 + 0x3f1) >> 5 & 1) == 0) && ((*(byte *)(iVar13 + 0x3f0) >> 2 & 1) == 0))
    {
      *(short *)(iVar13 + 0x484) =
           *(short *)(iVar13 + 0x484) + (short)*(undefined4 *)(iVar13 + 0x48c) * 0xb6;
    }
    *(undefined4 *)(iVar13 + 0x488) = 0;
    *(undefined4 *)(iVar13 + 0x48c) = 0;
  }
  dVar14 = (double)(((float)param_10[0xa6] - FLOAT_803e8bac) / FLOAT_803e8bc4);
  dVar17 = (double)FLOAT_803e8b3c;
  if ((dVar17 <= dVar14) && (dVar17 = dVar14, (double)FLOAT_803e8b78 < dVar14)) {
    dVar17 = (double)FLOAT_803e8b78;
  }
  dVar14 = (double)(*(float *)(iVar13 + 0x404) - FLOAT_803e8c04);
  *(float *)(iVar13 + 0x408) =
       (float)(dVar14 * (double)(float)(dVar17 * (double)*(float *)(iVar13 + 0x840)));
  bVar1 = *(byte *)(iVar13 + 0x3f0);
  if ((bVar1 >> 6 & 1) != 0) {
    *(uint *)(iVar13 + 0x360) = *(uint *)(iVar13 + 0x360) | 0x1000000;
    param_10[0xa8] = (uint)FLOAT_803e8d08;
    param_3 = (double)FLOAT_803e8c30;
    local_58 = (double)CONCAT44(0x43300000,*(uint *)(iVar13 + 0x858) ^ 0x80000000);
    sVar10 = (short)(int)(param_3 * (double)*(float *)(param_9 + 0x4c) +
                         (double)(float)(local_58 - DOUBLE_803e8b58));
    *(short *)(iVar13 + 0x478) = sVar10;
    *(int *)(iVar13 + 0x494) = (int)sVar10;
    if (*(char *)((int)param_10 + 0x346) != '\0') {
      *(byte *)(iVar13 + 0x3f0) = *(byte *)(iVar13 + 0x3f0) & 0xbf;
      *(short *)(iVar13 + 0x478) = *(short *)(iVar13 + 0x484);
      *(int *)(iVar13 + 0x494) = (int)*(short *)(iVar13 + 0x484);
      *(undefined *)(iVar13 + 0x8cc) = 0xc;
      *(byte *)(iVar13 + 0x3f1) = *(byte *)(iVar13 + 0x3f1) & 0xfb | 4;
      *(byte *)(iVar13 + 0x3f1) = *(byte *)(iVar13 + 0x3f1) & 0xf7 | 8;
    }
    param_2 = (double)*(float *)(iVar13 + 0x844);
    param_10[0xa5] = (uint)(float)(param_2 * (double)FLOAT_803dc074 + (double)(float)param_10[0xa5])
    ;
    *(float *)(iVar13 + 0x408) = FLOAT_803e8b3c;
    dVar14 = (double)*(float *)(param_9 + 0x4c);
    if (((double)FLOAT_803e8b94 < dVar14) && (dVar14 < (double)FLOAT_803e8d0c)) {
      *(ushort *)(iVar13 + 0x8d8) = *(ushort *)(iVar13 + 0x8d8) | 8;
    }
    goto LAB_802a611c;
  }
  if ((bVar1 >> 4 & 1) != 0) {
    dVar14 = (double)FUN_802aedb0((uint)param_9,iVar13,(int)param_10,param_12,param_13,param_14,
                                  param_15,param_16);
    goto LAB_802a611c;
  }
  if ((char)bVar1 < '\0') {
    iVar7 = FUN_802aebe0(dVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9
                         ,iVar13,(int)param_10,param_12,param_13,param_14,param_15,param_16);
    if (iVar7 != 0) {
      param_10[0xc2] = (uint)FUN_802a58ac;
      return 2;
    }
    goto LAB_802a611c;
  }
  if ((bVar1 >> 1 & 1) == 0) {
    if ((bVar1 >> 5 & 1) == 0) {
      if ((bVar1 >> 3 & 1) == 0) {
        if (((bVar1 >> 2 & 1) != 0) &&
           (iVar7 = FUN_802ada54(dVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                 param_9,iVar13,(int)param_10,(int)param_12,param_13,param_14,
                                 param_15,param_16), iVar7 != 0)) {
          param_10[0xc2] = (uint)FUN_802a58ac;
          return 2;
        }
      }
      else {
        FUN_802ae368((uint)param_9,iVar13,(int)param_10);
      }
    }
    else {
      dVar14 = (double)FUN_802ae5e0(param_9,iVar13,(int)param_10);
    }
    goto LAB_802a611c;
  }
  *(uint *)(iVar13 + 0x360) = *(uint *)(iVar13 + 0x360) | 0x800;
  fVar3 = FLOAT_803e8b3c;
  dVar14 = (double)FLOAT_803e8b3c;
  param_10[0xa5] = (uint)FLOAT_803e8b3c;
  param_10[0xa5] = (uint)fVar3;
  param_10[0xa1] = (uint)fVar3;
  param_10[0xa0] = (uint)fVar3;
  *(float *)(param_9 + 0x12) = fVar3;
  *(float *)(param_9 + 0x14) = fVar3;
  *(float *)(param_9 + 0x16) = fVar3;
  fVar4 = FLOAT_803e8c3c;
  *(float *)(iVar13 + 0x428) = FLOAT_803e8c3c;
  *(float *)(iVar13 + 0x42c) = fVar3;
  *(float *)(iVar13 + 0x430) = fVar4;
  *(float *)(iVar13 + 0x434) = fVar3;
  *(float *)(iVar13 + 0x408) = fVar3;
  uVar9 = FUN_80014e04(0);
  if ((uVar9 & 0x20) == 0) {
LAB_802a6018:
    if ((DAT_803df0cc != 0) && ((*(byte *)(iVar13 + 0x3f4) >> 6 & 1) != 0)) {
      *(undefined *)(iVar13 + 0x8b4) = 1;
      *(byte *)(iVar13 + 0x3f4) = *(byte *)(iVar13 + 0x3f4) & 0xf7 | 8;
    }
    FUN_8017082c();
    *(byte *)(iVar13 + 0x3f0) = *(byte *)(iVar13 + 0x3f0) & 0xfd;
    *(uint *)(iVar13 + 0x360) = *(uint *)(iVar13 + 0x360) | 0x800000;
    dVar14 = (double)FUN_80035f9c((int)param_9);
    bVar6 = true;
  }
  else {
    if (((((*(byte *)(iVar13 + 0x3f4) >> 6 & 1) == 0) ||
         (bVar1 = *(byte *)(iVar13 + 0x3f0), (bVar1 >> 5 & 1) != 0)) || ((bVar1 >> 3 & 1) != 0)) ||
       ((((((bVar1 >> 2 & 1) != 0 || (*(char *)(iVar13 + 0x8c8) == 'D')) ||
          ((*(int *)(iVar13 + 0x7f8) != 0 ||
           ((*(int *)(iVar13 + 0x2d0) != 0 || ((*(byte *)(iVar13 + 0x3f6) >> 6 & 1) != 0)))))) ||
         (*(short *)(iVar13 + 0x274) == 0x26)) ||
        (((param_9[0x58] & 0x1000U) != 0 ||
         (dVar14 = (double)*(float *)(iVar13 + 0x880), dVar14 != (double)FLOAT_803e8b3c)))))) {
      bVar6 = false;
    }
    else {
      bVar6 = true;
    }
    if (!bVar6) goto LAB_802a6018;
    bVar6 = false;
  }
  if (bVar6) {
    param_10[0xc2] = (uint)FUN_802a58ac;
    return 2;
  }
LAB_802a611c:
  bVar1 = *(byte *)(iVar13 + 0x3f0);
  if ((((((bVar1 >> 5 & 1) == 0) && ((bVar1 >> 6 & 1) == 0)) && ((bVar1 >> 4 & 1) == 0)) &&
      (((bVar1 >> 2 & 1) == 0 && ((bVar1 >> 3 & 1) == 0)))) &&
     (((bVar1 >> 1 & 1) == 0 &&
      ((*(int *)(iVar13 + 0x7f8) == 0 && (*(char *)(iVar13 + 0x8c8) != 'D')))))) {
    bVar6 = true;
  }
  else {
    bVar6 = false;
  }
  if ((bVar6) && ((*(ushort *)(iVar13 + 0x6e2) & 0x400) != 0)) {
    FUN_802af48c(dVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar13,
                 (int)param_10,param_12,param_13,param_14,param_15,param_16);
  }
  bVar1 = *(byte *)(iVar13 + 0x3f0);
  if (((((bVar1 >> 5 & 1) == 0) && ((bVar1 >> 6 & 1) == 0)) && (-1 < (char)bVar1)) &&
     ((((bVar1 >> 4 & 1) == 0 && ((bVar1 >> 2 & 1) == 0)) &&
      (((bVar1 >> 3 & 1) == 0 && ((*(byte *)(iVar13 + 0x3f1) >> 5 & 1) == 0)))))) {
    bVar6 = true;
  }
  else {
    bVar6 = false;
  }
  if (((bVar6) &&
      (fVar3 = (float)param_10[0xa5],
      (double)(FLOAT_803e8b44 + *(float *)(*(int *)(iVar13 + 0x400) + 0x14)) < (double)fVar3)) &&
     ((*(float *)(iVar13 + 0x470) < FLOAT_803e8cc8 || (0x95 < *(int *)(iVar13 + 0x488))))) {
    *(ushort *)(iVar13 + 0x8d8) = *(ushort *)(iVar13 + 0x8d8) | 8;
    *(byte *)(iVar13 + 0x3f0) = *(byte *)(iVar13 + 0x3f0) & 0x7f | 0x80;
    *(undefined *)(iVar13 + 0x8a6) = *(undefined *)(iVar13 + 0x8a7);
    *(uint *)(iVar13 + 0x360) = *(uint *)(iVar13 + 0x360) | 0x1000000;
    *(uint *)(iVar13 + 0x844) = param_10[0xa0];
    FUN_8003042c((double)FLOAT_803e8b3c,(double)fVar3,param_3,param_4,param_5,param_6,param_7,
                 param_8,param_9,(int)*(short *)(*(int *)(iVar13 + 0x3f8) + 0x3c),0,param_12,
                 param_13,param_14,param_15,param_16);
  }
  if (((-1 < (char)*(byte *)(iVar13 + 0x3f0)) && ((*(byte *)(iVar13 + 0x3f0) >> 6 & 1) == 0)) &&
     ((*(byte *)(iVar13 + 0x3f1) >> 5 & 1) == 0)) {
    if (*(int *)(iVar13 + 0x488) < 0x96) {
      local_50 = (double)CONCAT44(0x43300000,*(uint *)(iVar13 + 0x47c) ^ 0x80000000);
      dVar14 = FUN_80021434((double)(float)(local_50 - DOUBLE_803e8b58),
                            (double)(FLOAT_803e8b78 / *(float *)(iVar13 + 0x428)),
                            (double)FLOAT_803dc074);
      dVar15 = (double)(FLOAT_803dc074 * *(float *)(iVar13 + 0x42c) * *(float *)(iVar13 + 0x420));
      if (dVar15 < dVar14) {
        dVar14 = dVar15;
      }
      if (*(int *)(iVar13 + 0x480) < 0) {
        dVar14 = -dVar14;
      }
      param_3 = (double)FLOAT_803e8b98;
      local_58 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar13 + 0x478) ^ 0x80000000);
      *(short *)(iVar13 + 0x478) =
           (short)(int)(param_3 * dVar14 + (double)(float)(local_58 - DOUBLE_803e8b58));
    }
    if ((int)*(uint *)(iVar13 + 0x488) < 0x96) {
      local_48 = (double)CONCAT44(0x43300000,*(uint *)(iVar13 + 0x488) ^ 0x80000000);
      dVar14 = FUN_80021434((double)(float)(local_48 - DOUBLE_803e8b58),
                            (double)(FLOAT_803e8b78 / *(float *)(iVar13 + 0x430)),
                            (double)FLOAT_803dc074);
      dVar15 = (double)(*(float *)(iVar13 + 0x434) * FLOAT_803dc074);
      if (dVar15 < dVar14) {
        dVar14 = dVar15;
      }
      if (*(int *)(iVar13 + 0x48c) < 0) {
        dVar14 = -dVar14;
      }
      param_3 = (double)FLOAT_803e8b98;
      local_50 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar13 + 0x484) ^ 0x80000000);
      *(short *)(iVar13 + 0x484) =
           (short)(int)(param_3 * dVar14 + (double)(float)(local_50 - DOUBLE_803e8b58));
    }
    else {
      bVar1 = *(byte *)(iVar13 + 0x3f0);
      if ((((bVar1 >> 3 & 1) == 0) && ((bVar1 >> 2 & 1) == 0)) &&
         (((bVar1 >> 4 & 1) == 0 &&
          (((float)param_10[0xa5] <= *(float *)(*(int *)(iVar13 + 0x400) + 4) &&
           ((float)param_10[0xa0] <= *(float *)(*(int *)(iVar13 + 0x400) + 0xc))))))) {
        *(short *)(iVar13 + 0x484) =
             *(short *)(iVar13 + 0x484) + (short)*(undefined4 *)(iVar13 + 0x48c) * 0xb6;
      }
    }
  }
  bVar1 = *(byte *)(iVar13 + 0x3f1);
  if ((bVar1 >> 5 & 1) == 0) {
    bVar2 = *(byte *)(iVar13 + 0x3f0);
    if (((((((bVar2 >> 6 & 1) == 0) && ((bVar1 >> 2 & 1) == 0)) && ((bVar2 >> 4 & 1) == 0)) &&
         (((bVar1 >> 1 & 1) == 0 && ((bVar2 >> 3 & 1) == 0)))) && ((bVar2 >> 2 & 1) == 0)) &&
       ((bVar2 >> 1 & 1) == 0)) {
      dVar17 = FUN_80021434((double)(*(float *)(iVar13 + 0x408) - (float)param_10[0xa5]),
                            (double)*(float *)(iVar13 + 0x438),(double)FLOAT_803dc074);
      dVar15 = (double)FLOAT_803dc074;
      param_3 = (double)(float)((double)FLOAT_803e8b40 * dVar15);
      if ((param_3 <= dVar17) &&
         (param_3 = dVar17, (double)(float)((double)FLOAT_803e8b94 * dVar15) < dVar17)) {
        param_3 = (double)(float)((double)FLOAT_803e8b94 * dVar15);
      }
      if ((0x95 < *(int *)(iVar13 + 0x488)) && ((double)FLOAT_803e8b3c < param_3)) {
        param_3 = (double)(float)((double)FLOAT_803e8b6c * -param_3);
      }
      param_10[0xa5] = (uint)(float)((double)(float)param_10[0xa5] + param_3);
      fVar3 = (float)param_10[0xa5];
      fVar4 = **(float **)(iVar13 + 0x400);
      if ((fVar4 <= fVar3) && (fVar4 = fVar3, *(float *)(iVar13 + 0x404) < fVar3)) {
        fVar4 = *(float *)(iVar13 + 0x404);
      }
      param_10[0xa5] = (uint)fVar4;
      param_10[0xa1] = (uint)FLOAT_803e8b3c;
    }
    else if (((*(byte *)(iVar13 + 0x3f0) >> 3 & 1) == 0) &&
            ((*(byte *)(iVar13 + 0x3f0) >> 2 & 1) == 0)) {
      dVar15 = (double)(float)param_10[0xa5];
      dVar14 = (double)*(float *)(iVar13 + 0x404);
      dVar17 = -dVar14;
      if ((dVar17 <= dVar15) && (dVar17 = dVar15, dVar14 < dVar15)) {
        dVar17 = dVar14;
      }
      param_10[0xa5] = (uint)(float)dVar17;
    }
    else {
      dVar17 = (double)FUN_802945e0();
      dVar14 = (double)(float)((double)*(float *)(iVar13 + 0x408) * -dVar17);
      dVar17 = (double)FUN_80294964();
      dVar17 = (double)(float)((double)*(float *)(iVar13 + 0x408) * dVar17);
      if ((*(byte *)(iVar13 + 0x3f0) >> 2 & 1) == 0) {
        param_10[0xa5] = (uint)-(FLOAT_803e8bb8 * FLOAT_803dc074 - (float)param_10[0xa5]);
      }
      else {
        dVar15 = (double)FUN_802932a4((double)FLOAT_803e8c28,(double)FLOAT_803dc074);
        param_10[0xa5] = (uint)(float)((double)(float)param_10[0xa5] * dVar15);
      }
      fVar3 = (float)((double)FLOAT_803e8b24 * dVar17);
      fVar4 = FLOAT_803e8d10;
      if ((FLOAT_803e8d10 <= fVar3) && (fVar4 = fVar3, FLOAT_803e8d14 < fVar3)) {
        fVar4 = FLOAT_803e8d14;
      }
      param_10[0xa5] = (uint)(fVar4 * FLOAT_803dc074 + (float)param_10[0xa5]);
      fVar3 = (float)param_10[0xa5];
      fVar4 = FLOAT_803e8d18;
      if ((FLOAT_803e8d18 <= fVar3) &&
         (fVar5 = FLOAT_803e8b94 + *(float *)(iVar13 + 0x404), fVar4 = fVar3, fVar5 < fVar3)) {
        fVar4 = fVar5;
      }
      param_10[0xa5] = (uint)fVar4;
      dVar15 = (double)FLOAT_803e8d14;
      param_3 = (double)FLOAT_803dc074;
      dVar17 = FUN_80021434((double)((float)(dVar14 * (double)FLOAT_803e8c0c) -
                                    (float)param_10[0xa1]),dVar15,param_3);
      param_10[0xa1] = (uint)(float)((double)(float)param_10[0xa1] + dVar17);
    }
    if ((((*(byte *)(iVar13 + 0x3f0) >> 4 & 1) == 0) && ((*(byte *)(iVar13 + 0x3f1) >> 1 & 1) == 0))
       && ((*(byte *)(iVar13 + 0x3f0) >> 1 & 1) == 0)) {
      dVar15 = (double)*(float *)(iVar13 + 0x82c);
      param_3 = (double)FLOAT_803dc074;
      dVar17 = FUN_80021434((double)((float)param_10[0xa5] - (float)param_10[0xa0]),dVar15,param_3);
      param_10[0xa0] = (uint)(float)((double)(float)param_10[0xa0] + dVar17);
    }
    iVar7 = 0;
  }
  else {
    dVar14 = (double)FUN_802945e0();
    dVar15 = (double)(*(float *)(iVar13 + 0x404) * (float)(dVar17 * -dVar14));
    dVar14 = (double)FUN_80294964();
    dVar14 = (double)(*(float *)(iVar13 + 0x404) * (float)(dVar17 * -dVar14));
    dVar17 = FUN_80021434((double)(float)(dVar15 - (double)*(float *)(iVar13 + 0x4c8)),
                          (double)*(float *)(iVar13 + 0x438),(double)FLOAT_803dc074);
    dVar14 = FUN_80021434((double)(float)(dVar14 - (double)*(float *)(iVar13 + 0x4cc)),
                          (double)*(float *)(iVar13 + 0x438),(double)FLOAT_803dc074);
    *(float *)(iVar13 + 0x4c8) = (float)((double)*(float *)(iVar13 + 0x4c8) + dVar17);
    *(float *)(iVar13 + 0x4cc) = (float)((double)*(float *)(iVar13 + 0x4cc) + dVar14);
    dVar17 = FUN_80293900((double)(*(float *)(iVar13 + 0x4c8) * *(float *)(iVar13 + 0x4c8) +
                                  *(float *)(iVar13 + 0x4cc) * *(float *)(iVar13 + 0x4cc)));
    param_10[0xa5] = (uint)(float)dVar17;
    fVar3 = (float)param_10[0xa5];
    fVar4 = **(float **)(iVar13 + 0x400);
    if ((fVar4 <= fVar3) && (fVar4 = fVar3, *(float *)(iVar13 + 0x404) < fVar3)) {
      fVar4 = *(float *)(iVar13 + 0x404);
    }
    param_10[0xa5] = (uint)fVar4;
    dVar17 = (double)FUN_802945e0();
    dVar14 = (double)FUN_80294964();
    param_4 = (double)*(float *)(iVar13 + 0x4c8);
    dVar16 = (double)(float)(param_4 * dVar14 -
                            (double)(float)((double)*(float *)(iVar13 + 0x4cc) * dVar17));
    dVar17 = FUN_80021434((double)((float)(-(double)*(float *)(iVar13 + 0x4cc) * dVar14 -
                                          (double)(float)(param_4 * dVar17)) - (float)param_10[0xa0]
                                  ),(double)*(float *)(iVar13 + 0x82c),(double)FLOAT_803dc074);
    param_10[0xa0] = (uint)(float)((double)(float)param_10[0xa0] + dVar17);
    dVar15 = (double)*(float *)(iVar13 + 0x82c);
    param_3 = (double)FLOAT_803dc074;
    dVar17 = FUN_80021434((double)(float)(dVar16 - (double)(float)param_10[0xa1]),dVar15,param_3);
    param_10[0xa1] = (uint)(float)((double)(float)param_10[0xa1] + dVar17);
    dVar17 = (double)(float)param_10[0xa1];
    if (dVar17 < (double)FLOAT_803e8b3c) {
      dVar17 = -dVar17;
    }
    dVar14 = (double)(float)param_10[0xa0];
    if (dVar14 < (double)FLOAT_803e8b3c) {
      dVar14 = -dVar14;
    }
    iVar7 = FUN_8002f6cc((double)(float)param_10[0xa5],(int)param_9,(float *)(param_10 + 0xa8));
    if (iVar7 == 0) {
      param_10[0xa8] = (uint)FLOAT_803e8c10;
    }
    if ((*(byte *)(iVar13 + 0x3f0) >> 5 & 1) != 0) {
      param_10[0xa8] = (uint)((float)param_10[0xa8] * FLOAT_803e8b30);
    }
    if (dVar14 <= dVar17) {
      if ((float)param_10[0xa1] < FLOAT_803e8b3c) {
        iVar7 = 2;
      }
      else {
        iVar7 = 3;
      }
    }
    else if (FLOAT_803e8b3c <= (float)param_10[0xa0]) {
      iVar7 = 0;
    }
    else {
      iVar7 = 1;
    }
  }
  bVar1 = *(byte *)(iVar13 + 0x3f0);
  if (((-1 < (char)bVar1) && ((bVar1 >> 6 & 1) == 0)) &&
     (((bVar1 >> 4 & 1) == 0 &&
      ((((bVar1 >> 2 & 1) == 0 && ((bVar1 >> 3 & 1) == 0)) && ((bVar1 >> 1 & 1) == 0)))))) {
    bVar6 = (*(byte *)(iVar13 + 0x3f1) >> 3 & 1) == 0;
    fVar3 = FLOAT_803e8b3c;
    if (bVar6) {
      fVar3 = *(float *)(param_9 + 0x4c);
    }
    dVar17 = (double)fVar3;
    uVar8 = (uint)*(char *)(iVar13 + 0x8cc);
    uVar8 = ((int)uVar8 >> 2) + (uint)((int)uVar8 < 0 && (uVar8 & 3) != 0);
    *(char *)(iVar13 + 0x8b0) = (char)((int)(uVar8 * 2 | uVar8 >> 0x1f) >> 1) + '\x01';
    if (4 < *(byte *)(iVar13 + 0x8b0)) {
      *(undefined *)(iVar13 + 0x8b0) = 4;
    }
    if (*(byte *)(iVar13 + 0x8b0) < 4) {
      uVar11 = *(undefined *)(iVar13 + 0x8a3);
    }
    else {
      uVar11 = *(undefined *)(iVar13 + 0x8a4);
    }
    *(undefined *)(iVar13 + 0x8a6) = uVar11;
    fVar3 = (float)param_10[0xa5];
    iVar12 = *(int *)(iVar13 + 0x400);
    if (*(float *)(iVar12 + uVar8 * 8) <= fVar3) {
      if ((*(float *)(iVar12 + uVar8 * 8 + 4) <= fVar3) && (*(char *)(iVar13 + 0x8cc) < '\x14')) {
        if (*(char *)(iVar13 + 0x8cc) == '\0') {
          dVar17 = (double)FLOAT_803e8b3c;
        }
        if (fVar3 < *(float *)(iVar13 + 0x404)) {
          *(char *)(iVar13 + 0x8cc) = *(char *)(iVar13 + 0x8cc) + '\x04';
        }
      }
    }
    else if (*(char *)(iVar13 + 0x8cc) == '\x04') {
      if (((float)param_10[0xa0] < *(float *)(iVar12 + 0x10)) &&
         ((float)param_10[0xa6] < FLOAT_803e8bac)) {
        param_10[0xc2] = (uint)FUN_802a58ac;
        return 2;
      }
    }
    else {
      *(char *)(iVar13 + 0x8cc) = *(char *)(iVar13 + 0x8cc) + -4;
    }
    if (((((!bVar6) || (*(int *)(iVar13 + 0x3fc) != *(int *)(iVar13 + 0x3f8))) ||
         (param_9[0x50] !=
          *(short *)(*(int *)(iVar13 + 0x3f8) + (*(char *)(iVar13 + 0x8cc) + iVar7) * 2))) &&
        ((sVar10 = FUN_8002f604((int)param_9), sVar10 == 0 ||
         ((*(byte *)(iVar13 + 0x3f2) >> 4 & 1) != 0)))) &&
       ((FUN_8003042c(dVar17,dVar15,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                      (int)*(short *)(*(int *)(iVar13 + 0x3f8) +
                                     (*(char *)(iVar13 + 0x8cc) + iVar7) * 2),0,param_12,param_13,
                      param_14,param_15,param_16), (*(byte *)(iVar13 + 0x3f1) >> 5 & 1) != 0 &&
        (*(char *)((int)param_10 + 0x27a) == '\0')))) {
      FUN_8002f66c((int)param_9,0xc);
    }
  }
  local_48 = (double)CONCAT44(0x43300000,(int)*(short *)(param_10 + 0x67) ^ 0x80000000);
  dVar14 = (double)((float)(local_48 - DOUBLE_803e8b58) / FLOAT_803e8b80);
  dVar17 = (double)FLOAT_803e8b64;
  if ((dVar17 <= dVar14) && (dVar17 = dVar14, (double)FLOAT_803e8b78 < dVar14)) {
    dVar17 = (double)FLOAT_803e8b78;
  }
  dVar14 = dVar17;
  if (dVar17 < (double)FLOAT_803e8b3c) {
    dVar14 = -dVar17;
  }
  if (((((*(byte *)(iVar13 + 0x3f1) >> 5 & 1) == 0) &&
       (bVar1 = *(byte *)(iVar13 + 0x3f0), -1 < (char)bVar1)) && ((bVar1 >> 6 & 1) == 0)) &&
     ((((bVar1 >> 4 & 1) == 0 && ((bVar1 >> 2 & 1) == 0)) &&
      (((bVar1 >> 3 & 1) == 0 && ((bVar1 >> 1 & 1) == 0)))))) {
    if ((bVar1 >> 5 & 1) == 0) {
      FUN_8002ee64(dVar14,dVar15,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9,
                   (int)*(short *)(*(int *)(iVar13 + 0x3f8) +
                                   ((int)*(char *)(iVar13 + 0x8cc) +
                                   (uint)((double)FLOAT_803e8b3c < dVar17)) * 2 + 2),
                   (short)(int)((double)FLOAT_803e8c44 * dVar14));
    }
    iVar7 = FUN_8002f6cc((double)(float)param_10[0xa5],(int)param_9,(float *)(param_10 + 0xa8));
    if (iVar7 == 0) {
      param_10[0xa8] = (uint)FLOAT_803e8c10;
    }
  }
  FUN_802ac248(dVar17,param_9,(int)param_10,iVar13);
  return 0;
}

