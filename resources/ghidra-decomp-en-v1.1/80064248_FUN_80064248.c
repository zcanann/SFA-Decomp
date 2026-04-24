// Function: FUN_80064248
// Entry: 80064248
// Size: 1656 bytes

/* WARNING: Removing unreachable block (ram,0x800648a0) */
/* WARNING: Removing unreachable block (ram,0x80064898) */
/* WARNING: Removing unreachable block (ram,0x80064890) */
/* WARNING: Removing unreachable block (ram,0x80064888) */
/* WARNING: Removing unreachable block (ram,0x80064270) */
/* WARNING: Removing unreachable block (ram,0x80064268) */
/* WARNING: Removing unreachable block (ram,0x80064260) */
/* WARNING: Removing unreachable block (ram,0x80064258) */

void FUN_80064248(undefined4 param_1,undefined4 param_2,float *param_3,int *param_4,int *param_5,
                 undefined4 param_6,undefined4 param_7,uint param_8,byte param_9)

{
  float fVar1;
  undefined4 *puVar2;
  ushort uVar3;
  short sVar4;
  float *pfVar5;
  int iVar6;
  int *piVar7;
  int *piVar8;
  float *pfVar9;
  int *piVar10;
  undefined4 uVar11;
  undefined4 uVar12;
  uint uVar13;
  int *piVar14;
  int iVar15;
  int iVar16;
  bool bVar17;
  double dVar18;
  undefined8 extraout_f1;
  double dVar19;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  double in_f28;
  double in_f29;
  double in_f30;
  double dVar20;
  double in_f31;
  double dVar21;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar22;
  int local_d0;
  float local_cc;
  float local_c8;
  float local_c4;
  float local_c0;
  float local_bc;
  float local_b8;
  float local_b4;
  float local_b0;
  float local_ac;
  float local_a8;
  float local_a4;
  float local_a0 [2];
  undefined4 local_98;
  uint uStack_94;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  uVar22 = FUN_8028680c();
  pfVar9 = (float *)((ulonglong)uVar22 >> 0x20);
  pfVar5 = (float *)uVar22;
  DAT_803ddbcc = '\0';
  if (param_4 != (int *)0x0) {
    *(undefined *)(param_4 + 0x14) = 0xff;
    *(undefined *)((int)param_4 + 0x51) = 0xff;
  }
  if (param_5 == (int *)0x0) {
    iVar16 = 0;
  }
  else {
    iVar16 = param_5[0xc];
  }
  if (iVar16 == 0) {
    FUN_80003494((uint)&local_a8,(uint)pfVar9,0xc);
    FUN_80003494((uint)&local_b4,(uint)pfVar5,0xc);
  }
  else {
    FUN_8000e0c0((double)*pfVar9,(double)pfVar9[1],(double)pfVar9[2],&local_a8,&local_a4,local_a0,
                 iVar16);
    FUN_8000e0c0((double)*pfVar5,(double)pfVar5[1],(double)pfVar5[2],&local_b4,&local_b0,&local_ac,
                 iVar16);
  }
  puVar2 = FUN_80037048(6,&local_d0);
  iVar15 = 0;
  do {
    if (local_d0 <= iVar15) {
      FUN_80063524(&local_a8,&local_b4,(uint)param_3,param_4,0,(char)param_6,(char)param_7,param_9);
      if ((DAT_803ddbcc != '\0') && (param_4 != (int *)0x0)) {
        dVar21 = (double)((float)param_4[0xf] - (float)param_4[3]);
        dVar20 = (double)((float)param_4[0x10] - (float)param_4[4]);
        param_4[0xb] = (int)((float)param_4[6] - (float)param_4[5]);
        param_4[0xc] = (int)FLOAT_803df934;
        param_4[0xd] = (int)((float)param_4[1] - (float)param_4[2]);
        dVar19 = FUN_80293900((double)((float)param_4[0xb] * (float)param_4[0xb] +
                                      (float)param_4[0xd] * (float)param_4[0xd]));
        dVar18 = (double)FLOAT_803df944;
        param_4[0xb] = (int)((float)param_4[0xb] * (float)(dVar18 / dVar19));
        param_4[0xd] = (int)((float)param_4[0xd] * (float)(dVar18 / dVar19));
        param_4[0xe] = (int)-((float)param_4[0xb] * (float)param_4[1] +
                             (float)param_4[0xd] * (float)param_4[5]);
        if (*param_4 != 0) {
          FUN_8000e0c0((double)(float)param_4[1],(double)(float)param_4[3],(double)(float)param_4[5]
                       ,(float *)(param_4 + 1),(float *)(param_4 + 3),(float *)(param_4 + 5),
                       *param_4);
          FUN_8000e0c0((double)(float)param_4[2],(double)(float)param_4[4],(double)(float)param_4[6]
                       ,(float *)(param_4 + 2),(float *)(param_4 + 4),(float *)(param_4 + 6),
                       *param_4);
        }
        if (iVar16 != 0) {
          FUN_8000e054((double)(float)param_4[1],(double)(float)param_4[3],(double)(float)param_4[5]
                       ,(float *)(param_4 + 1),(float *)(param_4 + 3),(float *)(param_4 + 5),iVar16)
          ;
          FUN_8000e054((double)(float)param_4[2],(double)(float)param_4[4],(double)(float)param_4[6]
                       ,(float *)(param_4 + 2),(float *)(param_4 + 4),(float *)(param_4 + 6),iVar16)
          ;
        }
        param_4[7] = (int)((float)param_4[6] - (float)param_4[5]);
        param_4[8] = (int)FLOAT_803df934;
        param_4[9] = (int)((float)param_4[1] - (float)param_4[2]);
        dVar19 = FUN_80293900((double)((float)param_4[7] * (float)param_4[7] +
                                      (float)param_4[9] * (float)param_4[9]));
        dVar18 = (double)FLOAT_803df944;
        param_4[7] = (int)((float)param_4[7] * (float)(dVar18 / dVar19));
        param_4[9] = (int)((float)param_4[9] * (float)(dVar18 / dVar19));
        param_4[0xf] = (int)(float)((double)(float)param_4[3] + dVar21);
        param_4[0x10] = (int)(float)((double)(float)param_4[4] + dVar20);
        param_4[10] = (int)-((float)param_4[7] * (float)param_4[1] +
                            (float)param_4[9] * (float)param_4[5]);
      }
      if (DAT_803ddbcc != '\0') {
        if (iVar16 == 0) {
          FUN_80003494((uint)pfVar5,(uint)&local_b4,0xc);
        }
        else {
          FUN_8000e054((double)local_b4,(double)local_b0,(double)local_ac,pfVar5,pfVar5 + 1,
                       pfVar5 + 2,iVar16);
        }
      }
      FUN_80286858();
      return;
    }
    piVar14 = (int *)*puVar2;
    if ((((piVar14 != param_5) && (-1 < *(char *)((int)piVar14 + 0x35))) &&
        (*(int *)(piVar14[0x14] + 0x34) != 0)) &&
       ((iVar6 = piVar14[0x15], iVar6 == 0 || ((*(ushort *)(iVar6 + 0x60) & 1) != 0)))) {
      dVar21 = (double)((float)piVar14[3] - local_a8);
      dVar20 = (double)((float)piVar14[4] - local_a4);
      dVar19 = (double)((float)piVar14[5] - local_a0[0]);
      uVar3 = FUN_800284f8(**(int **)(piVar14[0x1f] + *(char *)(iVar6 + 0xb0) * 4));
      uStack_94 = uVar3 + 0x32 ^ 0x80000000;
      local_98 = 0x43300000;
      fVar1 = (float)((double)CONCAT44(0x43300000,uStack_94) - DOUBLE_803df958);
      dVar18 = (double)(fVar1 * fVar1);
      bVar17 = (double)(float)(dVar19 * dVar19 +
                              (double)(float)(dVar21 * dVar21 + (double)(float)(dVar20 * dVar20))) <
               dVar18;
      if ((!bVar17) &&
         ((double)(((float)piVar14[5] - local_ac) * ((float)piVar14[5] - local_ac) +
                  ((float)piVar14[3] - local_b4) * ((float)piVar14[3] - local_b4) +
                  ((float)piVar14[4] - local_b0) * ((float)piVar14[4] - local_b0)) < dVar18)) {
        bVar17 = true;
      }
      if (bVar17) {
        if ((param_8 & 0xff) == 0xff) {
LAB_8006451c:
          FUN_8000e054((double)local_a8,(double)local_a4,(double)local_a0[0],&local_c0,&local_bc,
                       &local_b8,(int)piVar14);
        }
        else {
          sVar4 = 0;
          piVar7 = DAT_803ddbc8;
          do {
            if (((*(char *)(piVar7 + 5) != '\0') && ((int *)*piVar7 == param_5)) &&
               (((int *)piVar7[1] == piVar14 &&
                ((uint)*(byte *)((int)piVar7 + 0x15) == (param_8 & 0xff))))) {
              *(undefined *)(piVar7 + 5) = 0;
              goto LAB_800644f8;
            }
            piVar7 = piVar7 + 6;
            sVar4 = sVar4 + 1;
          } while (sVar4 < 0x40);
          piVar7 = (int *)0x0;
LAB_800644f8:
          if (piVar7 == (int *)0x0) goto LAB_8006451c;
          local_c0 = (float)piVar7[2];
          local_bc = (float)piVar7[3];
          local_b8 = (float)piVar7[4];
        }
        dVar19 = (double)local_b0;
        dVar20 = (double)local_ac;
        FUN_8000e054((double)local_b4,dVar19,dVar20,&local_cc,&local_c8,&local_c4,(int)piVar14);
        pfVar9 = param_3;
        piVar7 = param_4;
        piVar10 = piVar14;
        uVar11 = param_6;
        uVar12 = param_7;
        uVar13 = (uint)param_9;
        iVar6 = FUN_80063524(&local_c0,&local_cc,(uint)param_3,param_4,(int)piVar14,(char)param_6,
                             (char)param_7,param_9);
        uVar22 = extraout_f1;
        if (iVar6 != 0) {
          dVar19 = (double)local_c8;
          dVar20 = (double)local_c4;
          pfVar9 = &local_ac;
          piVar7 = piVar14;
          uVar22 = FUN_8000e0c0((double)local_cc,dVar19,dVar20,&local_b4,&local_b0,&local_ac,
                                (int)piVar14);
        }
        if ((param_8 & 0xff) != 0xff) {
          sVar4 = 0;
          piVar8 = DAT_803ddbc8;
          do {
            if (*(char *)(piVar8 + 5) == '\0') {
              *piVar8 = (int)param_5;
              piVar8[1] = (int)piVar14;
              *(char *)((int)piVar8 + 0x15) = (char)param_8;
              *(undefined *)(piVar8 + 5) = 2;
              goto LAB_80064610;
            }
            piVar8 = piVar8 + 6;
            sVar4 = sVar4 + 1;
          } while (sVar4 < 0x40);
          FUN_80137c30(uVar22,dVar19,dVar20,dVar18,in_f5,in_f6,in_f7,in_f8,
                       s_NO_FREE_LAST_LINE_8030f428,piVar8,pfVar9,piVar7,piVar10,uVar11,uVar12,
                       uVar13);
          piVar8 = (int *)0x0;
LAB_80064610:
          if (piVar8 != (int *)0x0) {
            piVar8[2] = (int)local_cc;
            piVar8[3] = (int)local_c8;
            piVar8[4] = (int)local_c4;
          }
        }
      }
    }
    puVar2 = puVar2 + 1;
    iVar15 = iVar15 + 1;
  } while( true );
}

