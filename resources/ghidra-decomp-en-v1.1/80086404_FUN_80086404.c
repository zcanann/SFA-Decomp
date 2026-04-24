// Function: FUN_80086404
// Entry: 80086404
// Size: 1728 bytes

/* WARNING: Removing unreachable block (ram,0x80086aa4) */
/* WARNING: Removing unreachable block (ram,0x80086a9c) */
/* WARNING: Removing unreachable block (ram,0x8008641c) */
/* WARNING: Removing unreachable block (ram,0x80086414) */

void FUN_80086404(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,
                 undefined4 param_10,int *param_11,int *param_12,int *param_13,int param_14,
                 int *param_15,int param_16)

{
  short sVar1;
  bool bVar2;
  float fVar3;
  short *psVar4;
  short *psVar5;
  int iVar6;
  uint uVar7;
  int *piVar8;
  undefined2 uVar9;
  int iVar10;
  int iVar11;
  undefined **ppuVar12;
  double extraout_f1;
  double dVar13;
  double extraout_f1_00;
  double extraout_f1_01;
  double dVar14;
  double in_f30;
  double in_f31;
  double in_ps30_1;
  double in_ps31_1;
  float local_68;
  char *local_64;
  undefined auStack_60 [12];
  float local_54;
  float local_50;
  float local_4c;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  psVar4 = (short *)FUN_8028682c();
  if (param_11[0x25] != 0) {
    ppuVar12 = (undefined **)0x1;
    if (param_12 != (int *)0x0) {
      ppuVar12 = (undefined **)0x3;
    }
    iVar10 = *(int *)(psVar4 + 0x26);
    sVar1 = *(short *)(param_11 + 0x16);
    DAT_803ddd0a = sVar1;
    *(undefined2 *)((int)param_11 + 0x66) = 0;
    *(undefined2 *)(param_11 + 0x1a) = 0xffce;
    *(undefined *)(param_11 + 0x1e) = 0;
    *(undefined *)((int)param_11 + 0x7a) = 0;
    *(undefined *)((int)param_11 + 0x79) = 0;
    *param_11 = 0;
    *(undefined *)((int)param_11 + 0x7b) = 0;
    param_11[8] = (int)FLOAT_803dfc30;
    *(undefined2 *)(param_11 + 0x16) = 0xffff;
    uVar9 = 0xffff;
    iVar11 = 0;
    piVar8 = param_12;
    psVar5 = psVar4;
    dVar13 = extraout_f1;
    while ((iVar11 < *(short *)((int)param_11 + 0x62) && (*(short *)(param_11 + 0x16) <= sVar1))) {
      local_64 = (char *)(param_11[0x25] + iVar11 * 4);
      switch(*local_64) {
      case '\0':
        *(undefined2 *)(param_11 + 0x16) = *(undefined2 *)(local_64 + 2);
        break;
      default:
        if (*local_64 != '\x0f') {
          *(ushort *)(param_11 + 0x16) = *(short *)(param_11 + 0x16) + (ushort)(byte)local_64[1];
        }
        break;
      case '\x03':
        ppuVar12 = (undefined **)(int)(char)((byte)ppuVar12 | 4);
        psVar5 = FUN_80086050(dVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,psVar4,
                              param_11,iVar10,piVar8,param_13,param_14,param_15,param_16);
        psVar5[0x51] = -1;
        break;
      case '\t':
        uVar9 = *(undefined2 *)(param_11 + 0x16);
        break;
      case '\v':
        if (0 < *(short *)(local_64 + 2)) {
          iVar11 = iVar11 + *(short *)(local_64 + 2);
        }
      }
      iVar11 = iVar11 + 1;
    }
    *(undefined2 *)(param_11 + 0x16) = uVar9;
    iVar11 = *(int *)(*(int *)(psVar5 + 0x3e) + *(char *)((int)psVar5 + 0xad) * 4);
    if (iVar11 != 0) {
      if (param_11[0x26] == 0) {
        dVar13 = (double)FLOAT_803dfc30;
      }
      else {
        dVar13 = (double)FLOAT_803dfc30;
        if ((int)*(short *)(param_11 + 0x37) != 0) {
          dVar13 = FUN_80082e7c(dVar13,param_2,param_3,
                                (float *)(param_11[0x26] + *(short *)((int)param_11 + 0xb6) * 8),
                                (int)*(short *)(param_11 + 0x37) & 0xfff,-1);
        }
      }
      in_f31 = (double)(float)((double)*(float *)(iVar10 + 8) + dVar13);
      if (param_11[0x26] == 0) {
        dVar13 = (double)FLOAT_803dfc30;
      }
      else {
        dVar13 = (double)FLOAT_803dfc30;
        if ((int)*(short *)(param_11 + 0x36) != 0) {
          dVar13 = FUN_80082e7c(dVar13,param_2,param_3,
                                (float *)(param_11[0x26] + *(short *)((int)param_11 + 0xb2) * 8),
                                (int)*(short *)(param_11 + 0x36) & 0xfff,-1);
        }
      }
      in_f30 = (double)(float)((double)*(float *)(iVar10 + 0x10) + dVar13);
    }
    while (*(short *)(param_11 + 0x16) < sVar1) {
      *(short *)(param_11 + 0x16) = *(short *)(param_11 + 0x16) + 1;
      if (param_11[0x26] == 0) {
        dVar13 = (double)FLOAT_803dfc30;
      }
      else {
        dVar13 = (double)FLOAT_803dfc30;
        if ((int)*(short *)(param_11 + 0x37) != 0) {
          dVar13 = FUN_80082e7c(dVar13,param_2,param_3,
                                (float *)(param_11[0x26] + *(short *)((int)param_11 + 0xb6) * 8),
                                (int)*(short *)(param_11 + 0x37) & 0xfff,
                                (int)*(short *)(param_11 + 0x16));
        }
      }
      local_54 = (float)((double)*(float *)(iVar10 + 8) + dVar13);
      if (param_11[0x26] == 0) {
        dVar13 = (double)FLOAT_803dfc30;
      }
      else {
        dVar13 = (double)FLOAT_803dfc30;
        if ((int)*(short *)((int)param_11 + 0xda) != 0) {
          dVar13 = FUN_80082e7c(dVar13,param_2,param_3,
                                (float *)(param_11[0x26] + *(short *)(param_11 + 0x2d) * 8),
                                (int)*(short *)((int)param_11 + 0xda) & 0xfff,
                                (int)*(short *)(param_11 + 0x16));
        }
      }
      local_50 = (float)((double)*(float *)(iVar10 + 0xc) + dVar13);
      if (param_11[0x26] == 0) {
        dVar13 = (double)FLOAT_803dfc30;
      }
      else {
        dVar13 = (double)FLOAT_803dfc30;
        if ((int)*(short *)(param_11 + 0x36) != 0) {
          dVar13 = FUN_80082e7c(dVar13,param_2,param_3,
                                (float *)(param_11[0x26] + *(short *)((int)param_11 + 0xb2) * 8),
                                (int)*(short *)(param_11 + 0x36) & 0xfff,
                                (int)*(short *)(param_11 + 0x16));
        }
      }
      local_4c = (float)((double)*(float *)(iVar10 + 0x10) + dVar13);
      dVar13 = (double)local_4c;
      if ((0 < *(short *)(param_11 + 0x16)) && (param_12 != (int *)0x0)) {
        if ((*(char *)(param_11 + 0x1e) == '\x01') &&
           ((*(char *)((int)param_11 + 0x7b) == '\0' && (iVar11 != 0)))) {
          dVar14 = (double)(float)((double)local_54 - in_f31);
          dVar13 = FUN_80293900((double)(float)(dVar14 * dVar14 +
                                               (double)((float)(dVar13 - in_f30) *
                                                       (float)(dVar13 - in_f30))));
          iVar6 = FUN_8002f6cc(dVar13,(int)psVar5,&local_68);
          if (iVar6 == 0) {
            if (param_11[0x26] == 0) {
              dVar13 = (double)FLOAT_803dfc30;
            }
            else {
              dVar13 = (double)FLOAT_803dfc30;
              if ((int)*(short *)(param_11 + 0x35) != 0) {
                dVar13 = FUN_80082e7c(dVar13,dVar14,param_3,
                                      (float *)(param_11[0x26] +
                                               *(short *)((int)param_11 + 0xae) * 8),
                                      (int)*(short *)(param_11 + 0x35) & 0xfff,
                                      *(short *)(param_11 + 0x16) + -1);
              }
            }
            local_68 = (float)((double)FLOAT_803dfcb0 * dVar13);
          }
        }
        else {
          if (param_11[0x26] == 0) {
            dVar13 = (double)FLOAT_803dfc30;
          }
          else {
            dVar13 = (double)FLOAT_803dfc30;
            if ((int)*(short *)(param_11 + 0x35) != 0) {
              dVar13 = FUN_80082e7c(dVar13,param_2,param_3,
                                    (float *)(param_11[0x26] + *(short *)((int)param_11 + 0xae) * 8)
                                    ,(int)*(short *)(param_11 + 0x35) & 0xfff,
                                    *(short *)(param_11 + 0x16) + -1);
            }
          }
          local_68 = (float)((double)FLOAT_803dfcb0 * dVar13);
        }
        if (iVar11 == 0) {
          *(float *)(psVar5 + 0x4c) = *(float *)(psVar5 + 0x4c) + local_68;
          fVar3 = FLOAT_803dfc48;
          while (fVar3 < *(float *)(psVar5 + 0x4c)) {
            *(float *)(psVar5 + 0x4c) = *(float *)(psVar5 + 0x4c) - fVar3;
          }
          param_2 = (double)FLOAT_803dfc48;
          dVar14 = (double)FLOAT_803dfc30;
          while (dVar13 = (double)*(float *)(psVar5 + 0x4c), dVar13 < dVar14) {
            *(float *)(psVar5 + 0x4c) = (float)((double)*(float *)(psVar5 + 0x4c) + param_2);
          }
        }
        else {
          param_2 = (double)FLOAT_803dfc48;
          dVar13 = (double)FUN_8002fb40((double)local_68,param_2);
          if ((param_12 != (int *)0x0) &&
             (dVar13 = (double)FLOAT_803dfc30, dVar13 < (double)(float)param_11[8])) {
            uVar7 = (uint)*(short *)((int)param_11 + 0xd6);
            if (uVar7 == 0) {
              dVar13 = (double)FLOAT_803dfcb4;
            }
            else if ((param_11[0x26] != 0) && (uVar7 != 0)) {
              dVar13 = FUN_80082e7c(dVar13,param_2,param_3,
                                    (float *)(param_11[0x26] + *(short *)(param_11 + 0x2c) * 8),
                                    uVar7 & 0xfff,*(short *)(param_11 + 0x16) + -1);
            }
            if (dVar13 < (double)FLOAT_803dfc48) {
              dVar13 = (double)FLOAT_803dfc48;
            }
            param_11[8] = (int)((float)param_11[8] - (float)((double)FLOAT_803dfc48 / dVar13));
            dVar13 = (double)(float)param_11[8];
            if (dVar13 < (double)FLOAT_803dfc30) {
              param_11[8] = (int)FLOAT_803dfc30;
            }
          }
        }
      }
      in_f31 = (double)local_54;
      in_f30 = (double)local_4c;
      bVar2 = false;
      DAT_803ddd40 = 0;
      while ((!bVar2 &&
             ((int)*(short *)((int)param_11 + 0x66) < (int)*(short *)((int)param_11 + 0x62)))) {
        local_64 = (char *)(param_11[0x25] + *(short *)((int)param_11 + 0x66) * 4);
        if (*local_64 == '\0') {
          if (*(short *)(param_11 + 0x16) < *(short *)(local_64 + 2)) {
            bVar2 = true;
          }
          else {
            *(short *)(param_11 + 0x1a) = *(short *)(local_64 + 2);
            *(short *)((int)param_11 + 0x66) = *(short *)((int)param_11 + 0x66) + 1;
          }
        }
        else if (*(short *)(param_11 + 0x16) < *(short *)(param_11 + 0x1a)) {
          bVar2 = true;
        }
        else {
          if (*local_64 != '\x0f') {
            *(ushort *)(param_11 + 0x1a) = *(short *)(param_11 + 0x1a) + (ushort)(byte)local_64[1];
          }
          *(short *)((int)param_11 + 0x66) = *(short *)((int)param_11 + 0x66) + 1;
          iVar11 = FUN_800855e4(dVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                psVar4,iVar11,&local_64,ppuVar12,auStack_60,param_14,param_15,
                                param_16);
          if (iVar11 != 0) goto LAB_80086a9c;
          psVar5 = (short *)**(undefined4 **)(psVar4 + 0x5c);
          if ((short *)**(undefined4 **)(psVar4 + 0x5c) == (short *)0x0) {
            psVar5 = psVar4;
          }
          iVar11 = *(int *)(*(int *)(psVar5 + 0x3e) + *(char *)((int)psVar5 + 0xad) * 4);
          dVar13 = extraout_f1_00;
        }
      }
      for (iVar6 = 0; iVar6 < DAT_803ddd40; iVar6 = iVar6 + 1) {
        param_14 = (int)(short)(&DAT_8039a0b0)[iVar6 * 4];
        param_15 = (int *)0x1;
        param_16 = 0;
        iVar11 = FUN_8008399c(dVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,psVar4,
                              psVar5,(int)param_11,(uint *)(&DAT_8039a0ac)[iVar6 * 2],
                              (int)(short)(&DAT_8039a0b2)[iVar6 * 4],param_14,1,0);
        if (iVar11 != 0) {
          iVar6 = DAT_803ddd40;
        }
        psVar5 = (short *)**(undefined4 **)(psVar4 + 0x5c);
        if ((short *)**(undefined4 **)(psVar4 + 0x5c) == (short *)0x0) {
          psVar5 = psVar4;
        }
        iVar11 = *(int *)(*(int *)(psVar5 + 0x3e) + *(char *)((int)psVar5 + 0xad) * 4);
        dVar13 = extraout_f1_01;
      }
      DAT_803ddd40 = 0;
    }
  }
LAB_80086a9c:
  FUN_80286878();
  return;
}

