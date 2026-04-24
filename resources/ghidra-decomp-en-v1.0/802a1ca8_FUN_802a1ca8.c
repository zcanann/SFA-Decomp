// Function: FUN_802a1ca8
// Entry: 802a1ca8
// Size: 3184 bytes

/* WARNING: Removing unreachable block (ram,0x802a28e8) */
/* WARNING: Removing unreachable block (ram,0x802a28e0) */
/* WARNING: Removing unreachable block (ram,0x802a28f0) */

undefined4 FUN_802a1ca8(int param_1,uint *param_2)

{
  char cVar1;
  short sVar2;
  float fVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  undefined4 uVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  undefined8 in_f29;
  double dVar11;
  undefined8 in_f30;
  undefined8 in_f31;
  undefined auStack120 [4];
  undefined auStack116 [8];
  undefined auStack108 [4];
  float local_68;
  undefined auStack96 [4];
  float local_5c;
  undefined4 local_50;
  uint uStack76;
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
  iVar6 = *(int *)(param_1 + 0xb8);
  if (*(char *)((int)param_2 + 0x27a) != '\0') {
    FUN_80035e8c();
    if ((DAT_803de44c != 0) && ((*(byte *)(iVar6 + 0x3f4) >> 6 & 1) != 0)) {
      *(undefined *)(iVar6 + 0x8b4) = 1;
      *(byte *)(iVar6 + 0x3f4) = *(byte *)(iVar6 + 0x3f4) & 0xf7 | 8;
    }
    if ((*(short *)(param_1 + 0xa0) == DAT_80332f3c) || (*(short *)(param_1 + 0xa0) == DAT_80332f44)
       ) {
      DAT_803dc6a0 = 8;
    }
    else {
      DAT_803dc6a0 = 9;
    }
  }
  if (*(char *)(iVar6 + 0x4e4) < '\x04') {
    FUN_8011f3ec(0x1c);
  }
  else {
    FUN_8011f3ec(0x1a);
  }
  iVar5 = *(int *)(param_1 + 0xb8);
  *(uint *)(iVar5 + 0x360) = *(uint *)(iVar5 + 0x360) & 0xfffffffd;
  *(uint *)(iVar5 + 0x360) = *(uint *)(iVar5 + 0x360) | 0x2000;
  param_2[1] = param_2[1] | 0x100000;
  fVar3 = FLOAT_803e7ea4;
  dVar10 = (double)FLOAT_803e7ea4;
  param_2[0xa0] = (uint)FLOAT_803e7ea4;
  param_2[0xa1] = (uint)fVar3;
  *param_2 = *param_2 | 0x200000;
  *(float *)(param_1 + 0x24) = fVar3;
  *(float *)(param_1 + 0x2c) = fVar3;
  param_2[1] = param_2[1] | 0x8000000;
  if (FLOAT_803e7fa0 < *(float *)(iVar6 + 0x838)) {
    FUN_802ab5a4(param_1,iVar6,5);
    FUN_802ae83c(param_1,iVar6,param_2);
    param_2[0xc2] = (uint)FUN_802a514c;
    uVar4 = 2;
    goto LAB_802a28e0;
  }
  *(float *)(param_1 + 0x28) = fVar3;
  dVar8 = (double)((float)param_2[0xa3] / FLOAT_803e7fa8);
  if (dVar8 < dVar10) {
    dVar8 = -dVar8;
  }
  dVar10 = (double)FLOAT_803e7efc;
  if ((dVar10 <= dVar8) && (dVar10 = dVar8, (double)FLOAT_803e7ee0 < dVar8)) {
    dVar10 = (double)FLOAT_803e7ee0;
  }
  uVar4 = *(undefined4 *)(*(int *)(param_1 + 0x7c) + *(char *)(param_1 + 0xad) * 4);
  dVar8 = (double)FLOAT_803e7ea4;
  dVar11 = (double)(float)param_2[0xa8];
  DAT_803dc6a2 = DAT_803dc6a0;
  if ((param_2[0xc5] & 1) != 0) {
    if (*(char *)(iVar6 + 0x546) == '\x04') {
      FUN_8000bb18(param_1,0x33a);
    }
    else {
      FUN_8000bb18(param_1,0x11);
    }
  }
  if ((short)DAT_803dc6a0 < 10) {
    if ((short)DAT_803dc6a0 < 6) {
      if (3 < (short)DAT_803dc6a0) {
        if ((float)param_2[0xa3] <= FLOAT_803e7f10) {
          if (FLOAT_803e801c <= (float)param_2[0xa3]) {
            if (((param_2[199] & 0x100) != 0) && ('\x03' < *(char *)(iVar6 + 0x4e4))) {
              param_2[0xc2] = (uint)FUN_8029ffd0;
              uVar4 = 0xfffffff0;
              goto LAB_802a28e0;
            }
            goto LAB_802a2710;
          }
          FUN_80030304((double)FLOAT_803e7ea4,param_1);
        }
        else {
          FUN_80030304((double)FLOAT_803e7ea4,param_1);
        }
      }
LAB_802a21b0:
      if ((param_2[0xc5] & 0x80) != 0) {
        FUN_8000bb18(param_1,0x11);
      }
      if (((param_2[199] & 0x100) != 0) && ('\x03' < *(char *)(iVar6 + 0x4e4))) {
        param_2[0xc2] = (uint)FUN_8029ffd0;
        uVar4 = 0xfffffff0;
        goto LAB_802a28e0;
      }
      if (FLOAT_803e7ee0 == *(float *)(param_1 + 0x98)) {
        if (FLOAT_803e801c <= (float)param_2[0xa3]) {
          *(char *)(iVar6 + 0x4e4) = *(char *)(iVar6 + 0x4e4) + '\x01';
          *(undefined *)(iVar6 + 0x4e6) = 1;
          dVar11 = (double)FLOAT_803e7ea4;
          if ((short)DAT_803dc6a0 < 2) {
            DAT_803dc6a0 = DAT_803dc6a0 ^ 1;
            dVar8 = dVar11;
          }
          *(float *)(iVar6 + 0x4f8) = *(float *)(param_1 + 0x10) + *(float *)(iVar6 + 0x500);
          uStack76 = (int)*(char *)(iVar6 + 0x4e4) ^ 0x80000000;
          local_50 = 0x43300000;
          *(float *)(iVar6 + 0x4f4) =
               (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e7ec0) *
               *(float *)(iVar6 + 0x4f0) + *(float *)(iVar6 + 0x4ec);
          *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar6 + 0x4f8);
        }
        else {
          *(undefined *)(iVar6 + 0x4e6) = 0;
          dVar11 = -(double)(float)((double)FLOAT_803e7ef8 * dVar10 + (double)FLOAT_803e7f20);
          if ((short)DAT_803dc6a0 < 2) {
            DAT_803dc6a0 = DAT_803dc6a0 + 2;
            dVar8 = (double)FLOAT_803e7f68;
          }
        }
      }
      dVar9 = (double)FLOAT_803e7ea4;
      if (dVar9 == (double)*(float *)(param_1 + 0x98)) {
        if ((float)param_2[0xa3] <= FLOAT_803e7f10) {
          if (FLOAT_803e801c <= (float)param_2[0xa3]) {
            iVar5 = FUN_8002f50c(param_1);
            if (iVar5 != 0) goto LAB_802a2698;
            dVar8 = (double)FLOAT_803e7ea4;
            dVar11 = (double)FLOAT_803e7ef8;
            if (((DAT_803dc6a0 & 1) == 0) || (DAT_803dc6a0 == 5)) {
              if (((DAT_803dc6a0 & 1) == 0) && (DAT_803dc6a0 != 4)) {
                DAT_803dc6a0 = 4;
              }
            }
            else {
              DAT_803dc6a0 = 5;
            }
          }
          else {
            *(char *)(iVar6 + 0x4e4) = *(char *)(iVar6 + 0x4e4) + -1;
            *(undefined *)(iVar6 + 0x4e6) = 0;
            if ('\0' < *(char *)(iVar6 + 0x4e4)) {
              dVar8 = (double)FLOAT_803e7f68;
              dVar11 = -(double)(float)((double)FLOAT_803e7ef8 * dVar10 + (double)FLOAT_803e7f20);
              if ((DAT_803dc6a0 & 1) == 0) {
                DAT_803dc6a0 = 3;
              }
              else {
                DAT_803dc6a0 = 2;
              }
              uStack76 = (int)*(char *)(iVar6 + 0x4e4) ^ 0x80000000;
              local_50 = 0x43300000;
              *(float *)(iVar6 + 0x4f4) =
                   (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e7ec0) *
                   *(float *)(iVar6 + 0x4f0) + *(float *)(iVar6 + 0x4ec);
              fVar3 = *(float *)(param_1 + 0x10) - *(float *)(iVar6 + 0x500);
              *(float *)(iVar6 + 0x4f8) = fVar3;
              *(float *)(param_1 + 0x10) = fVar3;
              goto LAB_802a2698;
            }
            cVar1 = *(char *)(iVar6 + 0x8c8);
            if (((cVar1 != 'H') && (cVar1 != 'G')) && (cVar1 != 'B')) {
              (**(code **)(*DAT_803dca50 + 0x1c))(0x42,0,1,0,0,0x1e,0xff);
              *(undefined *)(iVar6 + 0x8c8) = 0x42;
            }
            fVar3 = FLOAT_803e7ea4;
            if (-1 < *(char *)(iVar6 + 0x547)) {
              param_2[0xa5] = (uint)FLOAT_803e7ea4;
              param_2[0xa1] = (uint)fVar3;
              param_2[0xa0] = (uint)fVar3;
              *(float *)(param_1 + 0x24) = fVar3;
              *(float *)(param_1 + 0x28) = fVar3;
              *(float *)(param_1 + 0x2c) = fVar3;
              *(byte *)(iVar6 + 0x3f0) = *(byte *)(iVar6 + 0x3f0) & 0x7f;
              *(byte *)(iVar6 + 0x3f0) = *(byte *)(iVar6 + 0x3f0) & 0xef;
              *(byte *)(iVar6 + 0x3f0) = *(byte *)(iVar6 + 0x3f0) & 0xf7;
              FUN_80170380(DAT_803de450,2);
              *(byte *)(iVar6 + 0x3f0) = *(byte *)(iVar6 + 0x3f0) & 0xfd;
              *(uint *)(iVar6 + 0x360) = *(uint *)(iVar6 + 0x360) | 0x800000;
              FUN_80035ea4(param_1);
              *(byte *)(iVar6 + 0x3f0) = *(byte *)(iVar6 + 0x3f0) & 0xbf;
              *(byte *)(iVar6 + 0x3f0) = *(byte *)(iVar6 + 0x3f0) & 0xfb | 4;
              *(byte *)(iVar6 + 0x3f4) = *(byte *)(iVar6 + 0x3f4) & 0xef | 0x10;
              *(undefined *)(iVar6 + 0x800) = 0;
              if (*(int *)(iVar6 + 0x7f8) != 0) {
                sVar2 = *(short *)(*(int *)(iVar6 + 0x7f8) + 0x46);
                if ((sVar2 == 0x3cf) || (sVar2 == 0x662)) {
                  FUN_80182504();
                }
                else {
                  FUN_800ea774();
                }
                *(ushort *)(*(int *)(iVar6 + 0x7f8) + 6) =
                     *(ushort *)(*(int *)(iVar6 + 0x7f8) + 6) & 0xbfff;
                *(undefined4 *)(*(int *)(iVar6 + 0x7f8) + 0xf8) = 0;
                *(undefined4 *)(iVar6 + 0x7f8) = 0;
              }
              FUN_802ab5a4(param_1,iVar6,5);
              param_2[0xc2] = (uint)FUN_802a514c;
              uVar4 = 3;
              goto LAB_802a28e0;
            }
            dVar8 = (double)FLOAT_803e7ea4;
            dVar11 = (double)FLOAT_803e7fe8;
            if ((DAT_803dc6a0 & 1) == 0) {
              DAT_803dc6a0 = 10;
            }
            else {
              DAT_803dc6a0 = 0xb;
            }
            *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar6 + 0x4ec);
          }
          goto LAB_802a2710;
        }
        *(undefined *)(iVar6 + 0x4e6) = 1;
        dVar8 = dVar9;
        if (*(char *)(iVar6 + 0x4e5) + -3 <= (int)*(char *)(iVar6 + 0x4e4)) {
          dVar11 = (double)FLOAT_803e8020;
          if ((DAT_803dc6a0 & 1) == 0) {
            DAT_803dc6a0 = 6;
          }
          else {
            DAT_803dc6a0 = 7;
          }
          FLOAT_803de438 = *(float *)(param_1 + 0x10);
          FLOAT_803de43c = *(float *)(iVar6 + 0x4e8) + DAT_803daf88;
          if ((*(char *)(iVar6 + 0x8c8) != 'H') && (*(char *)(iVar6 + 0x8c8) != 'G')) {
            (**(code **)(*DAT_803dca50 + 0x1c))(0x42,0,1,0,0,0x1e,0xff);
            dVar8 = dVar9;
          }
          goto LAB_802a2710;
        }
        dVar11 = (double)(float)((double)FLOAT_803e7f84 * dVar10 + (double)FLOAT_803e7f20);
        if (1 < (short)DAT_803dc6a0) {
          if ((DAT_803dc6a0 & 1) == 0) {
            DAT_803dc6a0 = 0;
          }
          else {
            DAT_803dc6a0 = 1;
          }
        }
      }
LAB_802a2698:
      if ((double)FLOAT_803e7ea4 <= dVar11) {
        if ((double)FLOAT_803e7ea4 < dVar11) {
          dVar11 = (double)(float)((double)FLOAT_803e7f84 * dVar10 + (double)FLOAT_803e7f20);
        }
      }
      else {
        dVar11 = -(double)(float)((double)FLOAT_803e7ef8 * dVar10 + (double)FLOAT_803e7f20);
      }
      if (*(char *)(iVar6 + 0x4e6) == '\0') {
        *(float *)(param_1 + 0x10) =
             (FLOAT_803e7ee0 - *(float *)(param_1 + 0x98)) *
             (*(float *)(iVar6 + 0x4f4) - *(float *)(iVar6 + 0x4f8)) + *(float *)(iVar6 + 0x4f8);
      }
      else {
        *(float *)(param_1 + 0x10) =
             *(float *)(param_1 + 0x98) * (*(float *)(iVar6 + 0x4f4) - *(float *)(iVar6 + 0x4f8)) +
             *(float *)(iVar6 + 0x4f8);
      }
    }
    else {
      if ((short)DAT_803dc6a0 < 8) {
        if (((param_2[0xc5] & 0x80) != 0) &&
           (FUN_8000bb18(param_1,0x10), *(short *)(iVar6 + 0x81a) == 0)) {
          FUN_8000bb18(param_1,0x398);
        }
        if (*(char *)((int)param_2 + 0x346) == '\0') {
          FUN_80027e00((double)FLOAT_803e7ea4,(double)*(float *)(param_1 + 8),uVar4,0,0,auStack96,
                       auStack116);
          FUN_80027e00((double)FLOAT_803e7ee0,(double)*(float *)(param_1 + 8),uVar4,0,0,auStack108,
                       auStack116);
          *(float *)(param_1 + 0x10) =
               *(float *)(param_1 + 0x98) *
               ((FLOAT_803de43c - (local_68 - local_5c)) - (FLOAT_803de438 + local_5c)) +
               FLOAT_803de438;
        }
        else {
          *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar6 + 0x4e8);
        }
        goto LAB_802a2010;
      }
LAB_802a1f08:
      *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar6 + 0x4f4);
      *(undefined2 *)(param_1 + 0xa2) = 0xffff;
      *(undefined *)(iVar6 + 0x4e6) = 0;
      *(undefined4 *)(iVar6 + 0x4f8) = *(undefined4 *)(iVar6 + 0x4f4);
      dVar11 = (double)FLOAT_803e7ea4;
      dVar8 = dVar11;
      if ((DAT_803dc6a0 & 1) == 0) {
        DAT_803dc6a0 = 0;
      }
      else {
        DAT_803dc6a0 = 1;
      }
    }
  }
  else {
    if (0xd < (short)DAT_803dc6a0) goto LAB_802a21b0;
    if (0xb < (short)DAT_803dc6a0) goto LAB_802a1f08;
LAB_802a2010:
    if (((param_2[0xc5] & 0x200) != 0) &&
       (FUN_80014aa0((double)FLOAT_803e7f10), FLOAT_803e7ea4 < *(float *)(iVar6 + 0x838))) {
      (**(code **)(*DAT_803dca98 + 0x10))
                ((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                 (double)*(float *)(param_1 + 0x14),(double)FLOAT_803e8018,param_1);
    }
    if (*(char *)((int)param_2 + 0x346) != '\0') {
      *(undefined4 *)(param_1 + 0x18) = *(undefined4 *)(iVar6 + 0x768);
      *(undefined4 *)(param_1 + 0x20) = *(undefined4 *)(iVar6 + 0x770);
      if (*(int *)(param_1 + 0x30) != 0) {
        *(float *)(param_1 + 0x18) = *(float *)(param_1 + 0x18) + FLOAT_803dcdd8;
        *(float *)(param_1 + 0x20) = *(float *)(param_1 + 0x20) + FLOAT_803dcddc;
      }
      FUN_8000e034((double)*(float *)(param_1 + 0x18),(double)FLOAT_803e7ea4,
                   (double)*(float *)(param_1 + 0x20),param_1 + 0xc,auStack120,param_1 + 0x14,
                   *(undefined4 *)(param_1 + 0x30));
      if ((DAT_803dc6a0 == 6) || (DAT_803dc6a0 == 7)) {
        FUN_802ab5a4(param_1,iVar6,7);
      }
      else {
        FUN_802ab5a4(param_1,iVar6,5);
      }
      FUN_80030334((double)FLOAT_803e7ea4,param_1,(int)**(short **)(iVar6 + 0x3f8),1);
      *(uint *)(iVar6 + 0x360) = *(uint *)(iVar6 + 0x360) | 0x800000;
      param_2[0xc2] = (uint)FUN_802a514c;
      uVar4 = 2;
      goto LAB_802a28e0;
    }
  }
LAB_802a2710:
  param_2[0xa8] = (uint)(float)dVar11;
  if ((((int)(short)DAT_803dc6a2 != (int)(short)DAT_803dc6a0) &&
      (FUN_80030334(dVar8,param_1,(int)(short)(&DAT_80332f2c)[(short)DAT_803dc6a0],1),
      (short)DAT_803dc6a0 < 2)) && (*(char *)(iVar6 + 0x4e7) == '\0')) {
    FUN_80027e00((double)FLOAT_803e7ea4,(double)*(float *)(param_1 + 8),uVar4,0,0,auStack96,
                 auStack116);
    FUN_80027e00((double)FLOAT_803e7ee0,(double)*(float *)(param_1 + 8),uVar4,0,0,auStack108,
                 auStack116);
    *(float *)(iVar6 + 0x500) = local_68 - local_5c;
    *(undefined *)(iVar6 + 0x4e7) = 1;
  }
  dVar10 = (double)*(float *)(param_1 + 0xc);
  dVar8 = (double)*(float *)(param_1 + 0x14);
  if ((short)DAT_803dc6a0 < 8) {
    if ((short)DAT_803dc6a0 < 4) {
      if ((short)DAT_803dc6a0 < 0) {
LAB_802a28b4:
        dVar11 = (double)*(float *)(param_1 + 0x10);
      }
      else {
        uStack76 = (int)*(char *)(iVar6 + 0x4e4) + 1U ^ 0x80000000;
        local_50 = 0x43300000;
        dVar11 = (double)(*(float *)(param_1 + 0x98) *
                          (((float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e7ec0) *
                            *(float *)(iVar6 + 0x4f0) + *(float *)(iVar6 + 0x4ec)) -
                          *(float *)(param_1 + 0x10)) + *(float *)(param_1 + 0x10));
      }
    }
    else {
      if ((short)DAT_803dc6a0 < 6) goto LAB_802a28b4;
      dVar9 = (double)*(float *)(param_1 + 0x98);
      dVar10 = (double)(float)(dVar9 * (double)(float)((double)*(float *)(iVar6 + 0x768) - dVar10) +
                              dVar10);
      dVar11 = (double)(float)(dVar9 * (double)(float)((double)*(float *)(iVar6 + 0x4e8) -
                                                      (double)*(float *)(param_1 + 0x10)) +
                              (double)*(float *)(param_1 + 0x10));
      dVar8 = (double)(float)(dVar9 * (double)(float)((double)*(float *)(iVar6 + 0x770) - dVar8) +
                             dVar8);
    }
  }
  else {
    if ((0xb < (short)DAT_803dc6a0) || ((short)DAT_803dc6a0 < 10)) goto LAB_802a28b4;
    dVar9 = (double)*(float *)(param_1 + 0x98);
    dVar10 = (double)(float)(dVar9 * (double)(float)((double)*(float *)(iVar6 + 0x768) - dVar10) +
                            dVar10);
    dVar11 = (double)((float)((double)FLOAT_803e7ee0 - dVar9) *
                      (*(float *)(iVar6 + 0x4f4) - *(float *)(param_1 + 0x10)) +
                     *(float *)(param_1 + 0x10));
    dVar8 = (double)(float)(dVar9 * (double)(float)((double)*(float *)(iVar6 + 0x770) - dVar8) +
                           dVar8);
  }
  (**(code **)(*DAT_803dca50 + 0x2c))(dVar10,dVar11,dVar8);
  FUN_802ab5a4(param_1,iVar6,5);
  uVar4 = 0;
LAB_802a28e0:
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  __psq_l0(auStack24,uVar7);
  __psq_l1(auStack24,uVar7);
  __psq_l0(auStack40,uVar7);
  __psq_l1(auStack40,uVar7);
  return uVar4;
}

