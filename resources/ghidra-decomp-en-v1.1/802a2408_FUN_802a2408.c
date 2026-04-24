// Function: FUN_802a2408
// Entry: 802a2408
// Size: 3184 bytes

/* WARNING: Removing unreachable block (ram,0x802a3050) */
/* WARNING: Removing unreachable block (ram,0x802a3048) */
/* WARNING: Removing unreachable block (ram,0x802a3040) */
/* WARNING: Removing unreachable block (ram,0x802a2428) */
/* WARNING: Removing unreachable block (ram,0x802a2420) */
/* WARNING: Removing unreachable block (ram,0x802a2418) */

undefined4
FUN_802a2408(undefined8 param_1,undefined8 param_2,double param_3,double param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,uint *param_10,
            undefined4 param_11,float *param_12,short *param_13,undefined4 param_14,
            undefined4 param_15,int param_16)

{
  char cVar1;
  float fVar2;
  short sVar3;
  int iVar4;
  int iVar5;
  int *piVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  float fStack_78;
  short asStack_74 [4];
  float fStack_6c;
  float local_68;
  float fStack_60;
  float local_5c;
  undefined4 local_50;
  uint uStack_4c;
  
  iVar5 = *(int *)(param_9 + 0xb8);
  if (*(char *)((int)param_10 + 0x27a) != '\0') {
    FUN_80035f84(param_9);
    if ((DAT_803df0cc != 0) && ((*(byte *)(iVar5 + 0x3f4) >> 6 & 1) != 0)) {
      *(undefined *)(iVar5 + 0x8b4) = 1;
      *(byte *)(iVar5 + 0x3f4) = *(byte *)(iVar5 + 0x3f4) & 0xf7 | 8;
    }
    if ((*(short *)(param_9 + 0xa0) == DAT_80333b9c) || (*(short *)(param_9 + 0xa0) == DAT_80333ba4)
       ) {
      DAT_803dd308 = 8;
    }
    else {
      DAT_803dd308 = 9;
    }
  }
  if (*(char *)(iVar5 + 0x4e4) < '\x04') {
    FUN_8011f6d0(0x1c);
  }
  else {
    FUN_8011f6d0(0x1a);
  }
  iVar4 = *(int *)(param_9 + 0xb8);
  *(uint *)(iVar4 + 0x360) = *(uint *)(iVar4 + 0x360) & 0xfffffffd;
  *(uint *)(iVar4 + 0x360) = *(uint *)(iVar4 + 0x360) | 0x2000;
  param_10[1] = param_10[1] | 0x100000;
  fVar2 = FLOAT_803e8b3c;
  dVar9 = (double)FLOAT_803e8b3c;
  param_10[0xa0] = (uint)FLOAT_803e8b3c;
  param_10[0xa1] = (uint)fVar2;
  *param_10 = *param_10 | 0x200000;
  *(float *)(param_9 + 0x24) = fVar2;
  *(float *)(param_9 + 0x2c) = fVar2;
  param_10[1] = param_10[1] | 0x8000000;
  if (FLOAT_803e8c38 < *(float *)(iVar5 + 0x838)) {
    FUN_802abd04(param_9,iVar5,5);
    FUN_802aef9c(param_9,iVar5);
    param_10[0xc2] = (uint)FUN_802a58ac;
    return 2;
  }
  *(float *)(param_9 + 0x28) = fVar2;
  dVar7 = (double)((float)param_10[0xa3] / FLOAT_803e8c40);
  if (dVar7 < dVar9) {
    dVar7 = -dVar7;
  }
  dVar11 = (double)FLOAT_803e8b94;
  if ((dVar11 <= dVar7) && (dVar11 = dVar7, (double)FLOAT_803e8b78 < dVar7)) {
    dVar11 = (double)FLOAT_803e8b78;
  }
  piVar6 = *(int **)(*(int *)(param_9 + 0x7c) + *(char *)(param_9 + 0xad) * 4);
  dVar7 = (double)FLOAT_803e8b3c;
  dVar10 = (double)(float)param_10[0xa8];
  DAT_803dd30a = DAT_803dd308;
  if ((param_10[0xc5] & 1) != 0) {
    if (*(char *)(iVar5 + 0x546) == '\x04') {
      FUN_8000bb38(param_9,0x33a);
    }
    else {
      FUN_8000bb38(param_9,0x11);
    }
  }
  if ((short)DAT_803dd308 < 10) {
    if ((short)DAT_803dd308 < 6) {
      if (3 < (short)DAT_803dd308) {
        if ((float)param_10[0xa3] <= FLOAT_803e8ba8) {
          if (FLOAT_803e8cb4 <= (float)param_10[0xa3]) {
            if (((param_10[199] & 0x100) != 0) && ('\x03' < *(char *)(iVar5 + 0x4e4))) {
              param_10[0xc2] = (uint)FUN_802a0730;
              return 0xfffffff0;
            }
            goto LAB_802a2e70;
          }
          FUN_800303fc((double)FLOAT_803e8b3c,param_9);
        }
        else {
          FUN_800303fc((double)FLOAT_803e8b3c,param_9);
        }
      }
LAB_802a2910:
      if ((param_10[0xc5] & 0x80) != 0) {
        FUN_8000bb38(param_9,0x11);
      }
      if (((param_10[199] & 0x100) != 0) && ('\x03' < *(char *)(iVar5 + 0x4e4))) {
        param_10[0xc2] = (uint)FUN_802a0730;
        return 0xfffffff0;
      }
      if (FLOAT_803e8b78 == *(float *)(param_9 + 0x98)) {
        if (FLOAT_803e8cb4 <= (float)param_10[0xa3]) {
          *(char *)(iVar5 + 0x4e4) = *(char *)(iVar5 + 0x4e4) + '\x01';
          *(undefined *)(iVar5 + 0x4e6) = 1;
          dVar10 = (double)FLOAT_803e8b3c;
          if ((short)DAT_803dd308 < 2) {
            DAT_803dd308 = DAT_803dd308 ^ 1;
            dVar7 = dVar10;
          }
          *(float *)(iVar5 + 0x4f8) = *(float *)(param_9 + 0x10) + *(float *)(iVar5 + 0x500);
          uStack_4c = (int)*(char *)(iVar5 + 0x4e4) ^ 0x80000000;
          local_50 = 0x43300000;
          *(float *)(iVar5 + 0x4f4) =
               (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e8b58) *
               *(float *)(iVar5 + 0x4f0) + *(float *)(iVar5 + 0x4ec);
          *(undefined4 *)(param_9 + 0x10) = *(undefined4 *)(iVar5 + 0x4f8);
        }
        else {
          *(undefined *)(iVar5 + 0x4e6) = 0;
          dVar10 = -(double)(float)((double)FLOAT_803e8b90 * dVar11 + (double)FLOAT_803e8bb8);
          if ((short)DAT_803dd308 < 2) {
            DAT_803dd308 = DAT_803dd308 + 2;
            dVar7 = (double)FLOAT_803e8c00;
          }
        }
      }
      dVar8 = (double)FLOAT_803e8b3c;
      if (dVar8 == (double)*(float *)(param_9 + 0x98)) {
        dVar9 = (double)(float)param_10[0xa3];
        if (dVar9 <= (double)FLOAT_803e8ba8) {
          if ((double)FLOAT_803e8cb4 <= dVar9) {
            sVar3 = FUN_8002f604(param_9);
            if (sVar3 != 0) goto LAB_802a2df8;
            dVar7 = (double)FLOAT_803e8b3c;
            dVar10 = (double)FLOAT_803e8b90;
            if (((DAT_803dd308 & 1) == 0) || (DAT_803dd308 == 5)) {
              if (((DAT_803dd308 & 1) == 0) && (DAT_803dd308 != 4)) {
                DAT_803dd308 = 4;
              }
            }
            else {
              DAT_803dd308 = 5;
            }
          }
          else {
            *(char *)(iVar5 + 0x4e4) = *(char *)(iVar5 + 0x4e4) + -1;
            *(undefined *)(iVar5 + 0x4e6) = 0;
            if ('\0' < *(char *)(iVar5 + 0x4e4)) {
              dVar7 = (double)FLOAT_803e8c00;
              dVar10 = -(double)(float)((double)FLOAT_803e8b90 * dVar11 + (double)FLOAT_803e8bb8);
              if ((DAT_803dd308 & 1) == 0) {
                DAT_803dd308 = 3;
              }
              else {
                DAT_803dd308 = 2;
              }
              uStack_4c = (int)*(char *)(iVar5 + 0x4e4) ^ 0x80000000;
              local_50 = 0x43300000;
              *(float *)(iVar5 + 0x4f4) =
                   (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e8b58) *
                   *(float *)(iVar5 + 0x4f0) + *(float *)(iVar5 + 0x4ec);
              fVar2 = *(float *)(param_9 + 0x10) - *(float *)(iVar5 + 0x500);
              *(float *)(iVar5 + 0x4f8) = fVar2;
              *(float *)(param_9 + 0x10) = fVar2;
              goto LAB_802a2df8;
            }
            cVar1 = *(char *)(iVar5 + 0x8c8);
            if (((cVar1 != 'H') && (cVar1 != 'G')) && (cVar1 != 'B')) {
              param_12 = (float *)0x0;
              param_13 = (short *)0x0;
              param_14 = 0x1e;
              param_15 = 0xff;
              param_16 = *DAT_803dd6d0;
              (**(code **)(param_16 + 0x1c))(0x42,0,1);
              *(undefined *)(iVar5 + 0x8c8) = 0x42;
            }
            fVar2 = FLOAT_803e8b3c;
            if (-1 < *(char *)(iVar5 + 0x547)) {
              param_10[0xa5] = (uint)FLOAT_803e8b3c;
              param_10[0xa1] = (uint)fVar2;
              param_10[0xa0] = (uint)fVar2;
              *(float *)(param_9 + 0x24) = fVar2;
              *(float *)(param_9 + 0x28) = fVar2;
              *(float *)(param_9 + 0x2c) = fVar2;
              *(byte *)(iVar5 + 0x3f0) = *(byte *)(iVar5 + 0x3f0) & 0x7f;
              *(byte *)(iVar5 + 0x3f0) = *(byte *)(iVar5 + 0x3f0) & 0xef;
              *(byte *)(iVar5 + 0x3f0) = *(byte *)(iVar5 + 0x3f0) & 0xf7;
              FUN_8017082c();
              *(byte *)(iVar5 + 0x3f0) = *(byte *)(iVar5 + 0x3f0) & 0xfd;
              *(uint *)(iVar5 + 0x360) = *(uint *)(iVar5 + 0x360) | 0x800000;
              FUN_80035f9c(param_9);
              *(byte *)(iVar5 + 0x3f0) = *(byte *)(iVar5 + 0x3f0) & 0xbf;
              *(byte *)(iVar5 + 0x3f0) = *(byte *)(iVar5 + 0x3f0) & 0xfb | 4;
              *(byte *)(iVar5 + 0x3f4) = *(byte *)(iVar5 + 0x3f4) & 0xef | 0x10;
              *(undefined *)(iVar5 + 0x800) = 0;
              iVar4 = *(int *)(iVar5 + 0x7f8);
              if (iVar4 != 0) {
                if ((*(short *)(iVar4 + 0x46) == 0x3cf) || (*(short *)(iVar4 + 0x46) == 0x662)) {
                  FUN_80182a5c(iVar4);
                }
                else {
                  FUN_800ea9f8(iVar4);
                }
                *(ushort *)(*(int *)(iVar5 + 0x7f8) + 6) =
                     *(ushort *)(*(int *)(iVar5 + 0x7f8) + 6) & 0xbfff;
                *(undefined4 *)(*(int *)(iVar5 + 0x7f8) + 0xf8) = 0;
                *(undefined4 *)(iVar5 + 0x7f8) = 0;
              }
              FUN_802abd04(param_9,iVar5,5);
              param_10[0xc2] = (uint)FUN_802a58ac;
              return 3;
            }
            dVar7 = (double)FLOAT_803e8b3c;
            dVar10 = (double)FLOAT_803e8c80;
            if ((DAT_803dd308 & 1) == 0) {
              DAT_803dd308 = 10;
            }
            else {
              DAT_803dd308 = 0xb;
            }
            *(undefined4 *)(param_9 + 0x10) = *(undefined4 *)(iVar5 + 0x4ec);
          }
          goto LAB_802a2e70;
        }
        *(undefined *)(iVar5 + 0x4e6) = 1;
        dVar7 = dVar8;
        if (*(char *)(iVar5 + 0x4e5) + -3 <= (int)*(char *)(iVar5 + 0x4e4)) {
          dVar10 = (double)FLOAT_803e8cb8;
          if ((DAT_803dd308 & 1) == 0) {
            DAT_803dd308 = 6;
          }
          else {
            DAT_803dd308 = 7;
          }
          FLOAT_803df0b8 = *(float *)(param_9 + 0x10);
          FLOAT_803df0bc = *(float *)(iVar5 + 0x4e8) + DAT_803dbbe8;
          if ((*(char *)(iVar5 + 0x8c8) != 'H') && (*(char *)(iVar5 + 0x8c8) != 'G')) {
            param_12 = (float *)0x0;
            param_13 = (short *)0x0;
            param_14 = 0x1e;
            param_15 = 0xff;
            param_16 = *DAT_803dd6d0;
            (**(code **)(param_16 + 0x1c))(0x42,0,1);
            dVar7 = dVar8;
          }
          goto LAB_802a2e70;
        }
        dVar10 = (double)(float)((double)FLOAT_803e8c1c * dVar11 + (double)FLOAT_803e8bb8);
        if (1 < (short)DAT_803dd308) {
          if ((DAT_803dd308 & 1) == 0) {
            DAT_803dd308 = 0;
          }
          else {
            DAT_803dd308 = 1;
          }
        }
      }
LAB_802a2df8:
      if ((double)FLOAT_803e8b3c <= dVar10) {
        if ((double)FLOAT_803e8b3c < dVar10) {
          dVar10 = (double)(float)((double)FLOAT_803e8c1c * dVar11 + (double)FLOAT_803e8bb8);
        }
      }
      else {
        dVar10 = -(double)(float)((double)FLOAT_803e8b90 * dVar11 + (double)FLOAT_803e8bb8);
      }
      if (*(char *)(iVar5 + 0x4e6) == '\0') {
        dVar9 = (double)*(float *)(iVar5 + 0x4f8);
        *(float *)(param_9 + 0x10) =
             (float)((double)(FLOAT_803e8b78 - *(float *)(param_9 + 0x98)) *
                     (double)(float)((double)*(float *)(iVar5 + 0x4f4) - dVar9) + dVar9);
      }
      else {
        dVar9 = (double)*(float *)(iVar5 + 0x4f8);
        *(float *)(param_9 + 0x10) =
             (float)((double)*(float *)(param_9 + 0x98) *
                     (double)(float)((double)*(float *)(iVar5 + 0x4f4) - dVar9) + dVar9);
      }
    }
    else {
      if (7 < (short)DAT_803dd308) goto LAB_802a2668;
      if (((param_10[0xc5] & 0x80) != 0) &&
         (FUN_8000bb38(param_9,0x10), *(short *)(iVar5 + 0x81a) == 0)) {
        FUN_8000bb38(param_9,0x398);
      }
      if (*(char *)((int)param_10 + 0x346) == '\0') {
        FUN_80027ec4((double)FLOAT_803e8b3c,(double)*(float *)(param_9 + 8),piVar6,0,0,&fStack_60,
                     asStack_74);
        param_12 = &fStack_6c;
        param_13 = asStack_74;
        FUN_80027ec4((double)FLOAT_803e8b78,(double)*(float *)(param_9 + 8),piVar6,0,0,param_12,
                     param_13);
        param_4 = (double)FLOAT_803df0b8;
        dVar9 = (double)*(float *)(param_9 + 0x98);
        param_3 = (double)local_5c;
        *(float *)(param_9 + 0x10) =
             (float)(dVar9 * (double)((FLOAT_803df0bc - (float)((double)local_68 - param_3)) -
                                     (float)(param_4 + param_3)) + param_4);
      }
      else {
        *(undefined4 *)(param_9 + 0x10) = *(undefined4 *)(iVar5 + 0x4e8);
      }
LAB_802a2770:
      if (((param_10[0xc5] & 0x200) != 0) &&
         (FUN_80014acc((double)FLOAT_803e8ba8), FLOAT_803e8b3c < *(float *)(iVar5 + 0x838))) {
        dVar9 = (double)*(float *)(param_9 + 0x10);
        param_3 = (double)*(float *)(param_9 + 0x14);
        param_4 = (double)FLOAT_803e8cb0;
        (**(code **)(*DAT_803dd718 + 0x10))((double)*(float *)(param_9 + 0xc),param_9);
      }
      if (*(char *)((int)param_10 + 0x346) != '\0') {
        *(undefined4 *)(param_9 + 0x18) = *(undefined4 *)(iVar5 + 0x768);
        *(undefined4 *)(param_9 + 0x20) = *(undefined4 *)(iVar5 + 0x770);
        if (*(int *)(param_9 + 0x30) != 0) {
          *(float *)(param_9 + 0x18) = *(float *)(param_9 + 0x18) + FLOAT_803dda58;
          *(float *)(param_9 + 0x20) = *(float *)(param_9 + 0x20) + FLOAT_803dda5c;
        }
        dVar9 = (double)FLOAT_803e8b3c;
        dVar7 = (double)*(float *)(param_9 + 0x20);
        iVar4 = *(int *)(param_9 + 0x30);
        FUN_8000e054((double)*(float *)(param_9 + 0x18),dVar9,dVar7,(float *)(param_9 + 0xc),
                     &fStack_78,(float *)(param_9 + 0x14),iVar4);
        if ((DAT_803dd308 == 6) || (DAT_803dd308 == 7)) {
          FUN_802abd04(param_9,iVar5,7);
        }
        else {
          FUN_802abd04(param_9,iVar5,5);
        }
        FUN_8003042c((double)FLOAT_803e8b3c,dVar9,dVar7,param_4,param_5,param_6,param_7,param_8,
                     param_9,(int)**(short **)(iVar5 + 0x3f8),1,iVar4,param_13,param_14,param_15,
                     param_16);
        *(uint *)(iVar5 + 0x360) = *(uint *)(iVar5 + 0x360) | 0x800000;
        param_10[0xc2] = (uint)FUN_802a58ac;
        return 2;
      }
    }
  }
  else {
    if (0xd < (short)DAT_803dd308) goto LAB_802a2910;
    if ((short)DAT_803dd308 < 0xc) goto LAB_802a2770;
LAB_802a2668:
    *(undefined4 *)(param_9 + 0x10) = *(undefined4 *)(iVar5 + 0x4f4);
    *(undefined2 *)(param_9 + 0xa2) = 0xffff;
    *(undefined *)(iVar5 + 0x4e6) = 0;
    *(undefined4 *)(iVar5 + 0x4f8) = *(undefined4 *)(iVar5 + 0x4f4);
    dVar10 = (double)FLOAT_803e8b3c;
    dVar7 = dVar10;
    if ((DAT_803dd308 & 1) == 0) {
      DAT_803dd308 = 0;
    }
    else {
      DAT_803dd308 = 1;
    }
  }
LAB_802a2e70:
  param_10[0xa8] = (uint)(float)dVar10;
  if ((((int)(short)DAT_803dd30a != (int)(short)DAT_803dd308) &&
      (FUN_8003042c(dVar7,dVar9,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                    (int)(short)(&DAT_80333b8c)[(short)DAT_803dd308],1,param_12,param_13,param_14,
                    param_15,param_16), (short)DAT_803dd308 < 2)) &&
     (*(char *)(iVar5 + 0x4e7) == '\0')) {
    FUN_80027ec4((double)FLOAT_803e8b3c,(double)*(float *)(param_9 + 8),piVar6,0,0,&fStack_60,
                 asStack_74);
    FUN_80027ec4((double)FLOAT_803e8b78,(double)*(float *)(param_9 + 8),piVar6,0,0,&fStack_6c,
                 asStack_74);
    *(float *)(iVar5 + 0x500) = local_68 - local_5c;
    *(undefined *)(iVar5 + 0x4e7) = 1;
  }
  dVar9 = (double)*(float *)(param_9 + 0xc);
  dVar7 = (double)*(float *)(param_9 + 0x14);
  if ((short)DAT_803dd308 < 8) {
    if ((short)DAT_803dd308 < 4) {
      if (-1 < (short)DAT_803dd308) {
        uStack_4c = (int)*(char *)(iVar5 + 0x4e4) + 1U ^ 0x80000000;
        local_50 = 0x43300000;
        dVar11 = (double)(*(float *)(param_9 + 0x98) *
                          (((float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e8b58) *
                            *(float *)(iVar5 + 0x4f0) + *(float *)(iVar5 + 0x4ec)) -
                          *(float *)(param_9 + 0x10)) + *(float *)(param_9 + 0x10));
        goto LAB_802a3018;
      }
    }
    else if (5 < (short)DAT_803dd308) {
      dVar10 = (double)*(float *)(param_9 + 0x98);
      dVar9 = (double)(float)(dVar10 * (double)(float)((double)*(float *)(iVar5 + 0x768) - dVar9) +
                             dVar9);
      dVar11 = (double)(float)(dVar10 * (double)(float)((double)*(float *)(iVar5 + 0x4e8) -
                                                       (double)*(float *)(param_9 + 0x10)) +
                              (double)*(float *)(param_9 + 0x10));
      dVar7 = (double)(float)(dVar10 * (double)(float)((double)*(float *)(iVar5 + 0x770) - dVar7) +
                             dVar7);
      goto LAB_802a3018;
    }
  }
  else if (((short)DAT_803dd308 < 0xc) && (9 < (short)DAT_803dd308)) {
    dVar10 = (double)*(float *)(param_9 + 0x98);
    dVar9 = (double)(float)(dVar10 * (double)(float)((double)*(float *)(iVar5 + 0x768) - dVar9) +
                           dVar9);
    dVar11 = (double)((float)((double)FLOAT_803e8b78 - dVar10) *
                      (*(float *)(iVar5 + 0x4f4) - *(float *)(param_9 + 0x10)) +
                     *(float *)(param_9 + 0x10));
    dVar7 = (double)(float)(dVar10 * (double)(float)((double)*(float *)(iVar5 + 0x770) - dVar7) +
                           dVar7);
    goto LAB_802a3018;
  }
  dVar11 = (double)*(float *)(param_9 + 0x10);
LAB_802a3018:
  (**(code **)(*DAT_803dd6d0 + 0x2c))(dVar9,dVar11,dVar7);
  FUN_802abd04(param_9,iVar5,5);
  return 0;
}

