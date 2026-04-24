// Function: FUN_800640cc
// Entry: 800640cc
// Size: 1656 bytes

/* WARNING: Removing unreachable block (ram,0x8006471c) */
/* WARNING: Removing unreachable block (ram,0x8006470c) */
/* WARNING: Removing unreachable block (ram,0x80064714) */
/* WARNING: Removing unreachable block (ram,0x80064724) */

void FUN_800640cc(undefined4 param_1,undefined4 param_2,undefined4 param_3,int *param_4,int param_5,
                 undefined4 param_6,undefined4 param_7,uint param_8,undefined param_9)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float *pfVar5;
  int *piVar6;
  uint uVar7;
  short sVar8;
  float *pfVar9;
  int iVar10;
  int *piVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  bool bVar15;
  undefined4 uVar16;
  double dVar17;
  undefined8 extraout_f1;
  double dVar18;
  undefined8 in_f28;
  undefined8 in_f29;
  undefined8 in_f30;
  double dVar19;
  undefined8 in_f31;
  double dVar20;
  undefined8 uVar21;
  int local_d0;
  float local_cc;
  float local_c8;
  float local_c4;
  int local_c0;
  int local_bc;
  int local_b8;
  float local_b4;
  float local_b0;
  float local_ac;
  float local_a8;
  float local_a4;
  float local_a0 [2];
  undefined4 local_98;
  uint uStack148;
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar16 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  uVar21 = FUN_802860a8();
  pfVar5 = (float *)((ulonglong)uVar21 >> 0x20);
  pfVar9 = (float *)uVar21;
  DAT_803dcf4c = '\0';
  if (param_4 != (int *)0x0) {
    *(undefined *)(param_4 + 0x14) = 0xff;
    *(undefined *)((int)param_4 + 0x51) = 0xff;
  }
  if (param_5 == 0) {
    iVar14 = 0;
  }
  else {
    iVar14 = *(int *)(param_5 + 0x30);
  }
  uVar21 = extraout_f1;
  if (iVar14 == 0) {
    FUN_80003494(&local_a8,pfVar5,0xc);
    FUN_80003494(&local_b4,pfVar9,0xc);
  }
  else {
    FUN_8000e0a0((double)*pfVar5,(double)pfVar5[1],(double)pfVar5[2],&local_a8,&local_a4,local_a0,
                 iVar14);
    FUN_8000e0a0((double)*pfVar9,(double)pfVar9[1],(double)pfVar9[2],&local_b4,&local_b0,&local_ac,
                 iVar14);
  }
  piVar6 = (int *)FUN_80036f50(6,&local_d0);
  iVar13 = 0;
  do {
    if (local_d0 <= iVar13) {
      FUN_800633a8(uVar21,&local_a8,&local_b4,param_3,param_4,0,param_6,param_7,param_9,param_5);
      if ((DAT_803dcf4c != '\0') && (param_4 != (int *)0x0)) {
        dVar20 = (double)((float)param_4[0xf] - (float)param_4[3]);
        dVar19 = (double)((float)param_4[0x10] - (float)param_4[4]);
        param_4[0xb] = (int)((float)param_4[6] - (float)param_4[5]);
        param_4[0xc] = (int)FLOAT_803decb4;
        param_4[0xd] = (int)((float)param_4[1] - (float)param_4[2]);
        dVar18 = (double)FUN_802931a0((double)((float)param_4[0xb] * (float)param_4[0xb] +
                                              (float)param_4[0xd] * (float)param_4[0xd]));
        dVar17 = (double)FLOAT_803decc4;
        param_4[0xb] = (int)((float)param_4[0xb] * (float)(dVar17 / dVar18));
        param_4[0xd] = (int)((float)param_4[0xd] * (float)(dVar17 / dVar18));
        param_4[0xe] = (int)-((float)param_4[0xb] * (float)param_4[1] +
                             (float)param_4[0xd] * (float)param_4[5]);
        if (*param_4 != 0) {
          FUN_8000e0a0((double)(float)param_4[1],(double)(float)param_4[3],(double)(float)param_4[5]
                       ,param_4 + 1,param_4 + 3,param_4 + 5);
          FUN_8000e0a0((double)(float)param_4[2],(double)(float)param_4[4],(double)(float)param_4[6]
                       ,param_4 + 2,param_4 + 4,param_4 + 6,*param_4);
        }
        if (iVar14 != 0) {
          FUN_8000e034((double)(float)param_4[1],(double)(float)param_4[3],(double)(float)param_4[5]
                       ,param_4 + 1,param_4 + 3,param_4 + 5,iVar14);
          FUN_8000e034((double)(float)param_4[2],(double)(float)param_4[4],(double)(float)param_4[6]
                       ,param_4 + 2,param_4 + 4,param_4 + 6,iVar14);
        }
        param_4[7] = (int)((float)param_4[6] - (float)param_4[5]);
        param_4[8] = (int)FLOAT_803decb4;
        param_4[9] = (int)((float)param_4[1] - (float)param_4[2]);
        dVar18 = (double)FUN_802931a0((double)((float)param_4[7] * (float)param_4[7] +
                                              (float)param_4[9] * (float)param_4[9]));
        dVar17 = (double)FLOAT_803decc4;
        param_4[7] = (int)((float)param_4[7] * (float)(dVar17 / dVar18));
        param_4[9] = (int)((float)param_4[9] * (float)(dVar17 / dVar18));
        param_4[0xf] = (int)(float)((double)(float)param_4[3] + dVar20);
        param_4[0x10] = (int)(float)((double)(float)param_4[4] + dVar19);
        param_4[10] = (int)-((float)param_4[7] * (float)param_4[1] +
                            (float)param_4[9] * (float)param_4[5]);
      }
      if (DAT_803dcf4c != '\0') {
        if (iVar14 == 0) {
          FUN_80003494(pfVar9,&local_b4,0xc);
        }
        else {
          FUN_8000e034((double)local_b4,(double)local_b0,(double)local_ac,pfVar9,pfVar9 + 1,
                       pfVar9 + 2,iVar14);
        }
      }
      __psq_l0(auStack8,uVar16);
      __psq_l1(auStack8,uVar16);
      __psq_l0(auStack24,uVar16);
      __psq_l1(auStack24,uVar16);
      __psq_l0(auStack40,uVar16);
      __psq_l1(auStack40,uVar16);
      __psq_l0(auStack56,uVar16);
      __psq_l1(auStack56,uVar16);
      FUN_802860f4(DAT_803dcf4c);
      return;
    }
    iVar12 = *piVar6;
    if ((((iVar12 != param_5) && (-1 < *(char *)(iVar12 + 0x35))) &&
        (*(int *)(*(int *)(iVar12 + 0x50) + 0x34) != 0)) &&
       ((iVar10 = *(int *)(iVar12 + 0x54), iVar10 == 0 || ((*(ushort *)(iVar10 + 0x60) & 1) != 0))))
    {
      dVar19 = (double)(*(float *)(iVar12 + 0xc) - local_a8);
      dVar18 = (double)(*(float *)(iVar12 + 0x10) - local_a4);
      dVar17 = (double)(*(float *)(iVar12 + 0x14) - local_a0[0]);
      uVar7 = FUN_80028434(**(undefined4 **)(*(int *)(iVar12 + 0x7c) + *(char *)(iVar10 + 0xb0) * 4)
                          );
      uStack148 = (uVar7 & 0xffff) + 0x32 ^ 0x80000000;
      local_98 = 0x43300000;
      fVar1 = (float)((double)CONCAT44(0x43300000,uStack148) - DOUBLE_803decd8);
      fVar1 = fVar1 * fVar1;
      bVar15 = (float)(dVar17 * dVar17 +
                      (double)(float)(dVar19 * dVar19 + (double)(float)(dVar18 * dVar18))) < fVar1;
      if ((!bVar15) &&
         (fVar2 = *(float *)(iVar12 + 0xc) - local_b4, fVar3 = *(float *)(iVar12 + 0x10) - local_b0,
         fVar4 = *(float *)(iVar12 + 0x14) - local_ac,
         fVar4 * fVar4 + fVar2 * fVar2 + fVar3 * fVar3 < fVar1)) {
        bVar15 = true;
      }
      if (bVar15) {
        if ((param_8 & 0xff) == 0xff) {
LAB_800643a0:
          FUN_8000e034((double)local_a8,(double)local_a4,(double)local_a0[0],&local_c0,&local_bc,
                       &local_b8,iVar12);
        }
        else {
          sVar8 = 0;
          piVar11 = DAT_803dcf48;
          do {
            if (((*(char *)(piVar11 + 5) != '\0') && (*piVar11 == param_5)) &&
               ((piVar11[1] == iVar12 && ((uint)*(byte *)((int)piVar11 + 0x15) == (param_8 & 0xff)))
               )) {
              *(undefined *)(piVar11 + 5) = 0;
              goto LAB_8006437c;
            }
            piVar11 = piVar11 + 6;
            sVar8 = sVar8 + 1;
          } while (sVar8 < 0x40);
          piVar11 = (int *)0x0;
LAB_8006437c:
          if (piVar11 == (int *)0x0) goto LAB_800643a0;
          local_c0 = piVar11[2];
          local_bc = piVar11[3];
          local_b8 = piVar11[4];
        }
        FUN_8000e034((double)local_b4,(double)local_b0,(double)local_ac,&local_cc,&local_c8,
                     &local_c4,iVar12);
        iVar10 = FUN_800633a8(uVar21,&local_c0,&local_cc,param_3,param_4,iVar12,param_6,param_7,
                              param_9,param_5);
        if (iVar10 != 0) {
          FUN_8000e0a0((double)local_cc,(double)local_c8,(double)local_c4,&local_b4,&local_b0,
                       &local_ac,iVar12);
        }
        if ((param_8 & 0xff) != 0xff) {
          sVar8 = 0;
          piVar11 = DAT_803dcf48;
          do {
            if (*(char *)(piVar11 + 5) == '\0') {
              *piVar11 = param_5;
              piVar11[1] = iVar12;
              *(char *)((int)piVar11 + 0x15) = (char)param_8;
              *(undefined *)(piVar11 + 5) = 2;
              goto LAB_80064494;
            }
            piVar11 = piVar11 + 6;
            sVar8 = sVar8 + 1;
          } while (sVar8 < 0x40);
          FUN_801378a8(s_NO_FREE_LAST_LINE_8030e868);
          piVar11 = (int *)0x0;
LAB_80064494:
          if (piVar11 != (int *)0x0) {
            piVar11[2] = (int)local_cc;
            piVar11[3] = (int)local_c8;
            piVar11[4] = (int)local_c4;
          }
        }
      }
    }
    piVar6 = piVar6 + 1;
    iVar13 = iVar13 + 1;
  } while( true );
}

