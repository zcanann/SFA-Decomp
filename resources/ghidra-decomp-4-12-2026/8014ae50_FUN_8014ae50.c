// Function: FUN_8014ae50
// Entry: 8014ae50
// Size: 3744 bytes

/* WARNING: Removing unreachable block (ram,0x8014bcd0) */
/* WARNING: Removing unreachable block (ram,0x8014bcc8) */
/* WARNING: Removing unreachable block (ram,0x8014bcc0) */
/* WARNING: Removing unreachable block (ram,0x8014bcb8) */
/* WARNING: Removing unreachable block (ram,0x8014ae78) */
/* WARNING: Removing unreachable block (ram,0x8014ae70) */
/* WARNING: Removing unreachable block (ram,0x8014ae68) */
/* WARNING: Removing unreachable block (ram,0x8014ae60) */

void FUN_8014ae50(undefined8 param_1,double param_2,double param_3,double param_4,double param_5,
                 double param_6,double param_7,undefined8 param_8,ushort *param_9,int *param_10,
                 undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
                 undefined4 param_15,undefined4 param_16)

{
  byte bVar1;
  float fVar2;
  ushort uVar3;
  float fVar4;
  uint uVar5;
  int iVar6;
  int *piVar7;
  float *pfVar8;
  undefined8 uVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  float fStack_d8;
  float local_d4;
  ushort local_d0;
  ushort local_ce;
  ushort local_cc;
  float local_c8;
  float local_c4;
  float local_c0;
  float local_bc;
  float local_b8;
  float local_b4;
  float local_b0;
  short local_aa;
  char local_a5 [8];
  char local_9d;
  float afStack_9c [17];
  longlong local_58;
  
  FUN_80003494((uint)(param_10 + 0xb1),(uint)(param_10 + 0xae),0xc);
  piVar7 = (int *)0xc;
  uVar9 = FUN_80003494((uint)(param_10 + 0xae),(uint)(param_9 + 0x12),0xc);
  if ((param_10[0xb9] & 0x400U) != 0) {
    uVar9 = FUN_8003b408((int)param_9,(int)(param_10 + 0x9b));
  }
  if ((param_10[0xa7] != 0) && ((param_10[0xb9] & 0x800U) != 0)) {
    piVar7 = param_10 + 0x9b;
    param_12 = 0x19;
    uVar9 = FUN_8003b1c8((short *)param_9,param_10[0xa7],(int)piVar7,0x19);
  }
  *(undefined *)(param_10 + 0xbc) = *(undefined *)((int)param_10 + 0x2ef);
  uVar5 = param_10[0xb7];
  if ((uVar5 & 0x800) != 0) {
    FUN_801491d4(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(uint)param_9,
                 (int)param_10,piVar7,param_12,param_13,param_14,param_15,param_16);
    goto LAB_8014b804;
  }
  if ((uVar5 & 0x1000) != 0) {
    FUN_80149040(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(uint)param_9,
                 (int)param_10,piVar7,param_12,param_13,param_14,param_15,param_16);
    goto LAB_8014b804;
  }
  if ((uVar5 & 0x20000000) == 0) {
    if ((uVar5 & 0x100) != 0) {
      *(undefined *)((int)param_10 + 0x2ef) = 2;
      if (((param_10[0xb7] & 0x100U) != 0) && ((param_10[0xb8] & 0x100U) == 0)) {
        param_2 = (double)(float)param_10[199];
        if ((double)FLOAT_803e31fc == param_2) {
          param_10[0xc2] = (int)FLOAT_803e3208;
        }
        else {
          param_10[0xc2] = (int)(FLOAT_803e3200 / (float)((double)FLOAT_803e3204 * param_2));
        }
        *(undefined *)((int)param_10 + 0x323) = 1;
        FUN_8003042c((double)FLOAT_803e31fc,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,(uint)*(byte *)((int)param_10 + 0x322),0x10,param_12,param_13,param_14,
                     param_15,param_16);
        if (*(int *)(param_9 + 0x2a) != 0) {
          *(undefined *)(*(int *)(param_9 + 0x2a) + 0x70) = 0;
        }
      }
      if ((param_10[0xb7] & 0x40000000U) == 0) {
        local_58 = (longlong)(int)(FLOAT_803e3210 * *(float *)(param_9 + 0x4c));
        *(char *)(param_9 + 0x1b) = (char)(int)(FLOAT_803e3210 * *(float *)(param_9 + 0x4c));
        param_9[3] = param_9[3] & 0xbfff;
      }
      else {
        param_10[0xc2] = (int)FLOAT_803e320c;
        *(undefined *)((int)param_10 + 0x323) = 0;
        FUN_8003042c((double)FLOAT_803e31fc,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,0,0,param_12,param_13,param_14,param_15,param_16);
        if (*(int *)(param_9 + 0x2a) != 0) {
          *(undefined *)(*(int *)(param_9 + 0x2a) + 0x70) = 0;
        }
        param_10[0xb7] = param_10[0xb7] & 0xfffffeff;
        *(undefined *)(param_9 + 0x1b) = 0xff;
      }
      goto LAB_8014b804;
    }
    *(undefined *)((int)param_10 + 0x2ef) = 5;
    uVar3 = param_9[0x23];
    if (uVar3 == 0x4d7) {
      FUN_801569d8(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10,
                   piVar7,param_12,param_13,param_14,param_15,param_16);
      goto LAB_8014b804;
    }
    if ((short)uVar3 < 0x4d7) {
      if (uVar3 == 0x281) {
LAB_8014b6e8:
        FUN_801524d4(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(uint)param_9,
                     (int)param_10);
        goto LAB_8014b804;
      }
      if ((short)uVar3 < 0x281) {
        if (uVar3 == 0x13a) {
LAB_8014b6d8:
          FUN_80150da4(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          goto LAB_8014b804;
        }
        if ((short)uVar3 < 0x13a) {
          if (uVar3 == 0xd8) goto LAB_8014b6e8;
          if (((short)uVar3 < 0xd8) && (uVar3 == 0x11)) goto LAB_8014b6d8;
        }
        else {
          if (uVar3 == 0x25d) {
            FUN_80155c80(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         (int *)param_9,(int)param_10);
            goto LAB_8014b804;
          }
          if (((short)uVar3 < 0x25d) && (uVar3 == 0x251)) {
            FUN_80154a30(param_9,param_10);
            goto LAB_8014b804;
          }
        }
      }
      else {
        if (uVar3 == 0x427) {
          FUN_801503b4();
          goto LAB_8014b804;
        }
        if ((short)uVar3 < 0x427) {
          if (uVar3 == 0x3fe) {
LAB_8014b718:
            FUN_801534ec(param_9,param_10);
            goto LAB_8014b804;
          }
          if (((short)uVar3 < 0x3fe) && (uVar3 == 0x369)) {
            FUN_801542b8(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         (short *)param_9,param_10);
            goto LAB_8014b804;
          }
        }
        else {
          if (uVar3 == 0x458) {
            FUN_801570e0(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(uint)param_9
                         ,(int)param_10);
            goto LAB_8014b804;
          }
          if ((short)uVar3 < 0x458) {
            if (0x456 < (short)uVar3) {
              FUN_801563cc(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           (int)param_9,(int)param_10);
              goto LAB_8014b804;
            }
          }
          else if (uVar3 == 0x4ac) {
            FUN_8015724c(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                         (int)param_10);
            goto LAB_8014b804;
          }
        }
      }
    }
    else {
      if (uVar3 == 0x7a6) goto LAB_8014b6d8;
      if ((short)uVar3 < 0x7a6) {
        if (uVar3 == 0x613) {
          FUN_801529c0(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          goto LAB_8014b804;
        }
        if ((short)uVar3 < 0x613) {
          if ((short)uVar3 < 0x5ba) {
            if (uVar3 == 0x58b) {
              FUN_80153ce8(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           (short *)param_9,(int)param_10);
              goto LAB_8014b804;
            }
            if ((0x58a < (short)uVar3) && (0x5b6 < (short)uVar3)) goto LAB_8014b6d8;
          }
          else if (uVar3 == 0x5e1) goto LAB_8014b6d8;
        }
        else if ((short)uVar3 < 0x6a2) {
          if (uVar3 == 0x642) {
            FUN_8015303c(param_9,(int)param_10);
            goto LAB_8014b804;
          }
        }
        else if ((short)uVar3 < 0x6a6) {
          FUN_80158940(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          goto LAB_8014b804;
        }
      }
      else {
        if (uVar3 == 0x842) {
LAB_8014b7a8:
          FUN_8015b0a8(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(uint)param_9,
                       (int)param_10);
          goto LAB_8014b804;
        }
        if ((short)uVar3 < 0x842) {
          if (uVar3 != 0x7c7) {
            if ((short)uVar3 < 0x7c7) {
              if (0x7c5 < (short)uVar3) goto LAB_8014b718;
            }
            else if ((short)uVar3 < 0x7c9) {
              FUN_80159e04(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                           param_10);
              goto LAB_8014b804;
            }
          }
        }
        else {
          if (uVar3 == 0x851) {
            FUN_8015b288((short *)param_9,(int)param_10);
            goto LAB_8014b804;
          }
          if (((short)uVar3 < 0x851) && (uVar3 == 0x84b)) goto LAB_8014b7a8;
        }
      }
    }
    FUN_801503b4();
    goto LAB_8014b804;
  }
  if ((uVar5 & 0x400) == 0) {
    *(undefined *)((int)param_10 + 0x2ef) = 4;
    uVar3 = param_9[0x23];
    if (uVar3 == 0x4d7) {
      FUN_80156708(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                   (int)param_10,piVar7,param_12,param_13,param_14,param_15,param_16);
      goto LAB_8014b804;
    }
    if ((short)uVar3 < 0x4d7) {
      if (uVar3 == 0x281) {
LAB_8014b338:
        FUN_801524d4(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(uint)param_9,
                     (int)param_10);
        goto LAB_8014b804;
      }
      if ((short)uVar3 < 0x281) {
        if (uVar3 == 0x13a) {
LAB_8014b328:
          FUN_80151370(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          goto LAB_8014b804;
        }
        if ((short)uVar3 < 0x13a) {
          if (uVar3 == 0xd8) goto LAB_8014b338;
          if (((short)uVar3 < 0xd8) && (uVar3 == 0x11)) goto LAB_8014b328;
        }
        else {
          if (uVar3 == 0x25d) {
            FUN_80155d30(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         (int *)param_9,(int)param_10);
            goto LAB_8014b804;
          }
          if (((short)uVar3 < 0x25d) && (uVar3 == 0x251)) {
            FUN_80154d1c(param_9,param_10);
            goto LAB_8014b804;
          }
        }
      }
      else {
        if (uVar3 == 0x427) {
          FUN_801503b4();
          goto LAB_8014b804;
        }
        if ((short)uVar3 < 0x427) {
          if (uVar3 == 0x3fe) {
LAB_8014b368:
            FUN_801536f4(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                         param_10);
            goto LAB_8014b804;
          }
          if (((short)uVar3 < 0x3fe) && (uVar3 == 0x369)) {
            FUN_8015454c(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         (short *)param_9,(int)param_10);
            goto LAB_8014b804;
          }
        }
        else {
          if (uVar3 == 0x458) {
            FUN_80156fb8(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(uint)param_9
                         ,(int)param_10);
            goto LAB_8014b804;
          }
          if ((short)uVar3 < 0x458) {
            if (0x456 < (short)uVar3) {
              FUN_801564bc(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           (uint)param_9,(int)param_10);
              goto LAB_8014b804;
            }
          }
          else if (uVar3 == 0x4ac) {
            FUN_801574b0(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            goto LAB_8014b804;
          }
        }
      }
    }
    else {
      if (uVar3 == 0x7a6) goto LAB_8014b328;
      if ((short)uVar3 < 0x7a6) {
        if (uVar3 == 0x613) {
          FUN_801529c0(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          goto LAB_8014b804;
        }
        if ((short)uVar3 < 0x613) {
          if ((short)uVar3 < 0x5ba) {
            if (uVar3 == 0x58b) {
              FUN_801540a8(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           (uint)param_9,(int)param_10);
              goto LAB_8014b804;
            }
            if ((0x58a < (short)uVar3) && (0x5b6 < (short)uVar3)) goto LAB_8014b328;
          }
          else if (uVar3 == 0x5e1) goto LAB_8014b328;
        }
        else if ((short)uVar3 < 0x6a2) {
          if (uVar3 == 0x642) {
            FUN_8015303c(param_9,(int)param_10);
            goto LAB_8014b804;
          }
        }
        else if ((short)uVar3 < 0x6a6) {
          FUN_801590d8(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          goto LAB_8014b804;
        }
      }
      else {
        if (uVar3 == 0x842) {
LAB_8014b3f8:
          FUN_8015add0(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                       (short *)param_9,(int)param_10);
          goto LAB_8014b804;
        }
        if ((short)uVar3 < 0x842) {
          if (uVar3 != 0x7c7) {
            if ((short)uVar3 < 0x7c7) {
              if (0x7c5 < (short)uVar3) goto LAB_8014b368;
            }
            else if ((short)uVar3 < 0x7c9) {
              FUN_8015a478((short *)param_9,param_10);
              goto LAB_8014b804;
            }
          }
        }
        else {
          if (uVar3 == 0x851) {
            FUN_8015b20c((short *)param_9,(int)param_10);
            goto LAB_8014b804;
          }
          if (((short)uVar3 < 0x851) && (uVar3 == 0x84b)) goto LAB_8014b3f8;
        }
      }
    }
    FUN_801503b4();
    goto LAB_8014b804;
  }
  *(undefined *)((int)param_10 + 0x2ef) = 3;
  uVar3 = param_9[0x23];
  if (uVar3 == 0x4d7) {
    FUN_80156708(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,(int)param_10
                 ,piVar7,param_12,param_13,param_14,param_15,param_16);
    goto LAB_8014b804;
  }
  if ((short)uVar3 < 0x4d7) {
    if (uVar3 == 0x281) {
LAB_8014b0b4:
      FUN_801524d4(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(uint)param_9,
                   (int)param_10);
      goto LAB_8014b804;
    }
    if ((short)uVar3 < 0x281) {
      if (uVar3 == 0x13a) {
LAB_8014b0a4:
        FUN_80151af0(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        goto LAB_8014b804;
      }
      if ((short)uVar3 < 0x13a) {
        if (uVar3 == 0xd8) goto LAB_8014b0b4;
        if (((short)uVar3 < 0xd8) && (uVar3 == 0x11)) goto LAB_8014b0a4;
      }
      else {
        if (uVar3 == 0x25d) {
          FUN_80155df4(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int *)param_9,
                       (int)param_10);
          goto LAB_8014b804;
        }
        if (((short)uVar3 < 0x25d) && (uVar3 == 0x251)) {
          FUN_80154d1c(param_9,param_10);
          goto LAB_8014b804;
        }
      }
    }
    else {
      if (uVar3 == 0x427) {
        FUN_801503b8((short *)param_9,param_10);
        goto LAB_8014b804;
      }
      if ((short)uVar3 < 0x427) {
        if (uVar3 == 0x3fe) {
LAB_8014b0e4:
          FUN_801536f4(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                       param_10);
          goto LAB_8014b804;
        }
        if (((short)uVar3 < 0x3fe) && (uVar3 == 0x369)) {
          FUN_8015454c(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                       (short *)param_9,(int)param_10);
          goto LAB_8014b804;
        }
      }
      else {
        if (uVar3 == 0x458) {
          FUN_80156fb8(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(uint)param_9,
                       (int)param_10);
          goto LAB_8014b804;
        }
        if ((short)uVar3 < 0x458) {
          if (0x456 < (short)uVar3) {
            FUN_801564bc(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(uint)param_9
                         ,(int)param_10);
            goto LAB_8014b804;
          }
        }
        else if (uVar3 == 0x4ac) {
          FUN_80157a04(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                       (int)param_10);
          goto LAB_8014b804;
        }
      }
    }
  }
  else {
    if (uVar3 == 0x7a6) goto LAB_8014b0a4;
    if ((short)uVar3 < 0x7a6) {
      if (uVar3 == 0x613) {
        FUN_801529c0(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        goto LAB_8014b804;
      }
      if ((short)uVar3 < 0x613) {
        if ((short)uVar3 < 0x5ba) {
          if (uVar3 == 0x58b) {
            FUN_801540a8(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(uint)param_9
                         ,(int)param_10);
            goto LAB_8014b804;
          }
          if ((0x58a < (short)uVar3) && (0x5b6 < (short)uVar3)) goto LAB_8014b0a4;
        }
        else if (uVar3 == 0x5e1) goto LAB_8014b0a4;
      }
      else if ((short)uVar3 < 0x6a2) {
        if (uVar3 == 0x642) {
          FUN_8015303c(param_9,(int)param_10);
          goto LAB_8014b804;
        }
      }
      else if ((short)uVar3 < 0x6a6) {
        FUN_80159730(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        goto LAB_8014b804;
      }
    }
    else {
      if (uVar3 == 0x842) {
LAB_8014b174:
        FUN_8015add0(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(short *)param_9,
                     (int)param_10);
        goto LAB_8014b804;
      }
      if ((short)uVar3 < 0x842) {
        if (uVar3 != 0x7c7) {
          if ((short)uVar3 < 0x7c7) {
            if (0x7c5 < (short)uVar3) goto LAB_8014b0e4;
          }
          else if ((short)uVar3 < 0x7c9) {
            FUN_80159e04(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                         param_10);
            goto LAB_8014b804;
          }
        }
      }
      else {
        if (uVar3 == 0x851) {
          FUN_8015b20c((short *)param_9,(int)param_10);
          goto LAB_8014b804;
        }
        if (((short)uVar3 < 0x851) && (uVar3 == 0x84b)) goto LAB_8014b174;
      }
    }
  }
  FUN_801503b8((short *)param_9,param_10);
LAB_8014b804:
  if (*(char *)((int)param_10 + 0x2ef) == *(char *)(param_10 + 0xbc)) {
    param_10[0xb7] = param_10[0xb7] & 0x7fffffff;
  }
  else {
    param_10[0xb7] = param_10[0xb7] | 0x80000000;
  }
  local_9d = '\0';
  iVar6 = FUN_8002fb40((double)(float)param_10[0xc2],(double)FLOAT_803dc074);
  if (iVar6 == 0) {
    param_10[0xb7] = param_10[0xb7] & 0xbfffffff;
  }
  else {
    param_10[0xb7] = param_10[0xb7] | 0x40000000;
  }
  *(undefined2 *)(param_10 + 0xbe) = 0;
  pfVar8 = &local_b8;
  for (iVar6 = 0; iVar6 < local_9d; iVar6 = iVar6 + 1) {
    *(ushort *)(param_10 + 0xbe) =
         *(ushort *)(param_10 + 0xbe) | (ushort)(1 << (int)*(char *)((int)pfVar8 + 0x13));
    pfVar8 = (float *)((int)pfVar8 + 1);
  }
  dVar13 = (double)FLOAT_803e31fc;
  if (((((param_10[0xb9] & 0x20U) != 0) && ((param_10[0xb9] & 0x400000U) == 0)) &&
      ((param_10[0xb7] & 0x1800U) == 0)) && ((*(byte *)((int)param_10 + 0x323) & 4) == 0)) {
    dVar13 = -(double)((float)param_10[0xc0] * FLOAT_803dc074 - *(float *)(param_9 + 0x14));
  }
  fVar2 = *(float *)(param_9 + 0x12);
  fVar4 = FLOAT_803e3260;
  if ((FLOAT_803e3260 <= fVar2) && (fVar4 = fVar2, FLOAT_803e3264 < fVar2)) {
    fVar4 = FLOAT_803e3264;
  }
  *(float *)(param_9 + 0x12) = fVar4;
  fVar2 = *(float *)(param_9 + 0x14);
  fVar4 = FLOAT_803e3260;
  if ((FLOAT_803e3260 <= fVar2) && (fVar4 = fVar2, FLOAT_803e3264 < fVar2)) {
    fVar4 = FLOAT_803e3264;
  }
  *(float *)(param_9 + 0x14) = fVar4;
  fVar2 = *(float *)(param_9 + 0x16);
  fVar4 = FLOAT_803e3260;
  if ((FLOAT_803e3260 <= fVar2) && (fVar4 = fVar2, FLOAT_803e3264 < fVar2)) {
    fVar4 = FLOAT_803e3264;
  }
  *(float *)(param_9 + 0x16) = fVar4;
  iVar6 = 0;
  uVar5 = param_10[0xb9];
  if (((uVar5 & 0x80) == 0) || (*(char *)((int)param_10 + 0x323) == '\0')) {
    if ((uVar5 & 0x100) == 0) {
      if ((uVar5 & 0x10) != 0) {
        iVar6 = 3;
      }
    }
    else {
      iVar6 = 2;
    }
  }
  else {
    iVar6 = 1;
  }
  if (((uVar5 & 0x200) != 0) && ((param_10[0xb7] & 0x4010U) != 0)) {
    iVar6 = 3;
  }
  if (iVar6 == 1) {
    dVar12 = (double)FLOAT_803e31fc;
    bVar1 = *(byte *)((int)param_10 + 0x323);
    dVar11 = dVar12;
    if ((bVar1 & 2) != 0) {
      dVar11 = (double)(local_b8 * FLOAT_803dc078);
    }
    dVar10 = dVar12;
    if ((bVar1 & 4) != 0) {
      dVar10 = (double)(local_b4 * FLOAT_803dc078);
    }
    if ((bVar1 & 1) != 0) {
      dVar12 = (double)(-local_b0 * FLOAT_803dc078);
    }
    if ((bVar1 & 8) != 0) {
      *param_9 = *param_9 + local_aa;
    }
    local_d0 = *param_9;
    local_ce = param_9[1];
    local_cc = param_9[2];
    local_c8 = FLOAT_803e3200;
    local_c4 = FLOAT_803e31fc;
    local_c0 = FLOAT_803e31fc;
    local_bc = FLOAT_803e31fc;
    FUN_80021fac(afStack_9c,&local_d0);
    if ((*(byte *)((int)param_10 + 0x323) & 4) == 0) {
      FUN_80022790(dVar11,(double)FLOAT_803e31fc,-dVar12,afStack_9c,(float *)(param_9 + 0x12),
                   &fStack_d8,(float *)(param_9 + 0x16));
    }
    else {
      FUN_80022790(dVar11,dVar10,-dVar12,afStack_9c,(float *)(param_9 + 0x12),
                   (float *)(param_9 + 0x14),(float *)(param_9 + 0x16));
    }
  }
  else if (iVar6 == 2) {
    dVar11 = FUN_80293900((double)(*(float *)(param_9 + 0x12) * *(float *)(param_9 + 0x12) +
                                  *(float *)(param_9 + 0x16) * *(float *)(param_9 + 0x16)));
    iVar6 = FUN_8002f6cc(dVar11,(int)param_9,&local_d4);
    if (iVar6 != 0) {
      param_10[0xc2] = (int)local_d4;
    }
  }
  else if ((iVar6 == 3) && ((*(byte *)((int)param_10 + 0x2f1) & 0x80) == 0)) {
    dVar11 = (double)FUN_802932a4((double)(float)param_10[0xc1],(double)FLOAT_803dc074);
    *(float *)(param_9 + 0x12) = (float)((double)*(float *)(param_9 + 0x12) * dVar11);
    dVar11 = (double)FUN_802932a4((double)(float)param_10[0xc1],(double)FLOAT_803dc074);
    *(float *)(param_9 + 0x14) = (float)((double)*(float *)(param_9 + 0x14) * dVar11);
    dVar11 = (double)FUN_802932a4((double)(float)param_10[0xc1],(double)FLOAT_803dc074);
    *(float *)(param_9 + 0x16) = (float)((double)*(float *)(param_9 + 0x16) * dVar11);
  }
  FUN_8014aa5c((int)param_9,(int)param_10);
  if (((param_10[0xb9] & 0x400000U) == 0) && ((param_10[0xb7] & 0x8100000U) == 0)) {
    if ((param_10[0xb9] & 0x20U) == 0) {
      if ((*(byte *)((int)param_10 + 0x2f1) & 0x80) == 0) {
        FUN_8002ba34((double)(*(float *)(param_9 + 0x12) * FLOAT_803dc074),
                     (double)(*(float *)(param_9 + 0x14) * FLOAT_803dc074),
                     (double)(*(float *)(param_9 + 0x16) * FLOAT_803dc074),(int)param_9);
      }
    }
    else if ((*(byte *)((int)param_10 + 0x2f1) & 0x80) == 0) {
      FUN_8002ba34((double)(*(float *)(param_9 + 0x12) * FLOAT_803dc074),
                   (double)(-(FLOAT_803e3268 *
                              (float)param_10[0xc0] * FLOAT_803dc074 * FLOAT_803dc074 -
                             (*(float *)(param_9 + 0x14) * FLOAT_803dc074 + *(float *)(param_9 + 8))
                             ) - *(float *)(param_9 + 8)),
                   (double)(*(float *)(param_9 + 0x16) * FLOAT_803dc074),(int)param_9);
      *(float *)(param_9 + 0x14) = (float)dVar13;
    }
  }
  else if ((*(byte *)((int)param_10 + 0x2f1) & 0x80) == 0) {
    FUN_8002ba34((double)(*(float *)(param_9 + 0x12) * FLOAT_803dc074),
                 (double)(*(float *)(param_9 + 0x14) * FLOAT_803dc074),
                 (double)(*(float *)(param_9 + 0x16) * FLOAT_803dc074),(int)param_9);
  }
  return;
}

