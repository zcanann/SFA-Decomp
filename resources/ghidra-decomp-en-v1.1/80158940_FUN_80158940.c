// Function: FUN_80158940
// Entry: 80158940
// Size: 1944 bytes

/* WARNING: Removing unreachable block (ram,0x801590b8) */
/* WARNING: Removing unreachable block (ram,0x80158950) */

void FUN_80158940(undefined8 param_1,undefined8 param_2,double param_3,double param_4,double param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  float fVar1;
  uint uVar2;
  ushort *puVar3;
  char cVar5;
  int iVar4;
  undefined4 *puVar6;
  undefined4 *puVar7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  float *pfVar8;
  undefined *puVar9;
  undefined *puVar10;
  undefined *puVar11;
  undefined *puVar12;
  double dVar13;
  double extraout_f1;
  double extraout_f1_00;
  double dVar14;
  double dVar15;
  undefined8 uVar16;
  
  uVar16 = FUN_80286838();
  puVar3 = (ushort *)((ulonglong)uVar16 >> 0x20);
  puVar6 = (undefined4 *)uVar16;
  uVar2 = (uint)*(byte *)((int)puVar6 + 0x33b);
  puVar12 = (&PTR_DAT_80320740)[uVar2 * 8];
  puVar11 = (&PTR_DAT_80320738)[uVar2 * 8];
  puVar10 = (&PTR_DAT_8032074c)[uVar2 * 8];
  puVar9 = (&PTR_DAT_80320744)[uVar2 * 8];
  pfVar8 = (float *)*puVar6;
  dVar15 = (double)FLOAT_803e383c;
  puVar6[0xba] = puVar6[0xba] & 0xffffffbf;
  if (*(int *)(puVar3 + 100) != 0) {
    FUN_80220104(*(int *)(puVar3 + 100));
  }
  if ((puVar6[0xb7] & 0x80000000) != 0) {
    *(byte *)((int)puVar6 + 0x33d) = *(byte *)((int)puVar6 + 0x33d) | 8;
    cVar5 = (**(code **)(*DAT_803dd71c + 0x8c))
                      ((double)FLOAT_803e3840,*puVar6,puVar3,&DAT_803dc958,0xffffffff);
    if (cVar5 != '\0') {
      puVar6[0xb7] = puVar6[0xb7] & 0xffffdfff;
    }
    if (*(char *)((int)puVar6 + 0x33b) == '\0') {
      FUN_80157e34(puVar3);
    }
    *(undefined *)((int)puVar6 + 0x33a) = 0;
  }
  fVar1 = FLOAT_803e3840;
  dVar14 = (double)(float)puVar6[0xca];
  dVar13 = (double)FLOAT_803e3840;
  if ((dVar14 != dVar13) && (*(char *)((int)puVar6 + 0x33f) != '\0')) {
    puVar6[0xca] = (float)(dVar14 - (double)FLOAT_803dc074);
    if ((double)(float)puVar6[0xca] <= dVar13) {
      puVar6[0xca] = fVar1;
      puVar6[0xb7] = puVar6[0xb7] | 0x40000000;
      *(char *)(puVar6 + 0xcf) =
           (char)*(undefined4 *)(puVar10 + (uint)*(byte *)((int)puVar6 + 0x33f) * 0x10 + 0xc);
      *(byte *)(puVar3 + 0x72) = *(byte *)(puVar6 + 0xcf) & 1;
      *(undefined *)((int)puVar6 + 0x33f) =
           puVar10[(uint)*(byte *)((int)puVar6 + 0x33f) * 0x10 + 10];
    }
    if ((puVar6[0xb7] & 0xc0000000) == 0) goto LAB_801590b8;
  }
  if ((puVar6[0xb7] & 0x2000) == 0) {
    if ((puVar6[0xb7] & 0xc0000000) != 0) {
      uVar2 = FUN_80022264(1,(uint)(byte)puVar12[8]);
      iVar4 = (uVar2 & 0xff) * 0xc;
      dVar13 = (double)FUN_8014d504((double)*(float *)(puVar12 + iVar4),dVar14,param_3,param_4,
                                    param_5,param_6,param_7,param_8,(int)puVar3,(int)puVar6,
                                    (uint)(byte)puVar12[iVar4 + 8],0,(uint)(byte)puVar12[iVar4 + 10]
                                    ,in_r8,in_r9,in_r10);
    }
  }
  else {
    puVar7 = &DAT_803ad108;
    iVar4 = FUN_8014c594(puVar3,1,0x28,&DAT_803ad108);
    if ((0 < iVar4) &&
       ((float)((double)CONCAT44(0x43300000,(uint)DAT_803ad10c) - DOUBLE_803e3828) <= FLOAT_803e3850
       )) {
      uVar2 = FUN_80021884();
      uVar2 = (uVar2 & 0xffff) - (uint)*puVar3;
      if (0x8000 < (int)uVar2) {
        uVar2 = uVar2 - 0xffff;
      }
      if ((int)uVar2 < -0x8000) {
        uVar2 = uVar2 + 0xffff;
      }
      uVar2 = (uVar2 & 0xffff) >> 0xd;
      if ((uVar2 == 3) || (uVar2 == 4)) {
        dVar15 = (double)((float)((double)CONCAT44(0x43300000,(uint)DAT_803ad10c) - DOUBLE_803e3828)
                         / FLOAT_803e3850);
      }
      else if ((uVar2 == 0) || (uVar2 == 7)) {
        param_3 = (double)FLOAT_803e384c;
        dVar15 = (double)(float)(param_3 * (double)(float)((double)FLOAT_803e383c -
                                                          (double)((float)((double)CONCAT44(
                                                  0x43300000,(uint)DAT_803ad10c) - DOUBLE_803e3828)
                                                  / FLOAT_803e3850)) + (double)FLOAT_803e383c);
      }
    }
    dVar13 = FUN_80293900((double)((pfVar8[0x1a] - *(float *)(puVar3 + 6)) *
                                   (pfVar8[0x1a] - *(float *)(puVar3 + 6)) +
                                  (pfVar8[0x1c] - *(float *)(puVar3 + 10)) *
                                  (pfVar8[0x1c] - *(float *)(puVar3 + 10))));
    if ((double)FLOAT_803e3838 < dVar13) {
      dVar13 = (double)FLOAT_803e3838;
    }
    dVar14 = (double)FLOAT_803e3838;
    puVar6[0xc4] = (float)(dVar15 * (double)((float)((double)(float)(dVar14 - dVar13) / dVar14) *
                                            (float)puVar6[0xbf]));
    if ((float)puVar6[0xc4] < FLOAT_803e3854) {
      puVar6[0xc4] = FLOAT_803e3854;
    }
    dVar13 = (double)(float)puVar6[0xc4];
    iVar4 = FUN_80010340(dVar13,pfVar8);
    if (((iVar4 != 0) || (pfVar8[4] != 0.0)) &&
       (cVar5 = (**(code **)(*DAT_803dd71c + 0x90))(pfVar8), dVar13 = extraout_f1, cVar5 != '\0')) {
      puVar7 = (undefined4 *)0xffffffff;
      cVar5 = (**(code **)(*DAT_803dd71c + 0x8c))
                        ((double)FLOAT_803e3858,*puVar6,puVar3,&DAT_803dc958);
      dVar13 = extraout_f1_00;
      if (cVar5 != '\0') {
        puVar6[0xb7] = puVar6[0xb7] & 0xffffdfff;
      }
    }
    if ((*(byte *)((int)puVar6 + 0x33d) & 10) == 0) {
      uVar2 = FUN_80021884();
      param_4 = (double)(float)((double)CONCAT44(0x43300000,
                                                 ((uVar2 & 0xffff) + 0x8000) - (uint)*puVar3 ^
                                                 0x80000000) - DOUBLE_803e3830);
      if ((double)FLOAT_803e3860 < param_4) {
        param_4 = (double)(float)((double)FLOAT_803e385c + param_4);
      }
      if (param_4 < (double)FLOAT_803e3868) {
        param_4 = (double)(float)((double)FLOAT_803e3864 + param_4);
      }
      param_3 = (double)((float)((double)(float)puVar6[0xbf] * dVar15 - (double)(float)puVar6[0xc4])
                        / FLOAT_803e381c);
      dVar14 = (double)FLOAT_803e383c;
      dVar15 = param_4;
      if (param_4 < (double)FLOAT_803e3840) {
        dVar15 = -param_4;
      }
      puVar6[0xc2] = (float)(param_3 *
                            (double)(float)(dVar14 - (double)(float)(dVar15 / (double)FLOAT_803e3864
                                                                    )));
      dVar13 = (double)(float)puVar6[0xc2];
      if ((double)FLOAT_803e386c <= dVar13) {
        if ((double)FLOAT_803e3870 < dVar13) {
          puVar6[0xc2] = FLOAT_803e3870;
        }
      }
      else {
        puVar6[0xc2] = FLOAT_803e386c;
      }
    }
    if ((puVar6[0xb7] & 0xc0000000) != 0) {
      *(byte *)((int)puVar6 + 0x33d) = *(byte *)((int)puVar6 + 0x33d) & 0xdf;
      if (*(byte *)((int)puVar6 + 0x33f) == 0) {
        dVar14 = -(double)(*(float *)(puVar3 + 0x10) - pfVar8[0x1c]);
        uVar2 = FUN_80021884();
        uVar2 = (uVar2 & 0xffff) - (uint)*puVar3;
        if (0x8000 < (int)uVar2) {
          uVar2 = uVar2 - 0xffff;
        }
        if ((int)uVar2 < -0x8000) {
          uVar2 = uVar2 + 0xffff;
        }
        iVar4 = ((uVar2 & 0xffff) >> 0xd) * 0xc;
        puVar10 = puVar9 + iVar4;
        if ((byte)puVar10[8] == 0) {
          *(byte *)((int)puVar6 + 0x33d) = *(byte *)((int)puVar6 + 0x33d) & 0xe7;
          fVar1 = (float)puVar6[0xc4];
          iVar4 = (uint)*(byte *)((int)puVar6 + 0x33b) * 0xc;
          if (fVar1 <= *(float *)(&DAT_80320798 + iVar4)) {
            if (fVar1 <= *(float *)(&DAT_8032079c + iVar4)) {
              if (fVar1 <= *(float *)(&DAT_803207a0 + iVar4)) {
                *(undefined *)((int)puVar6 + 0x323) = 1;
                puVar6[0xc2] = FLOAT_803e3874;
                dVar13 = (double)FUN_8003042c((double)FLOAT_803e3840,dVar14,param_3,param_4,param_5,
                                              param_6,param_7,param_8,puVar3,(uint)(byte)puVar11[8],
                                              0,puVar7,puVar10,in_r8,in_r9,in_r10);
                puVar6[0xc4] = FLOAT_803e3840;
              }
              else {
                *(undefined *)((int)puVar6 + 0x323) = 1;
                dVar13 = (double)FUN_8003042c((double)FLOAT_803e3840,dVar14,param_3,param_4,param_5,
                                              param_6,param_7,param_8,puVar3,
                                              (uint)(byte)puVar11[0x14],0,puVar7,puVar10,in_r8,in_r9
                                              ,in_r10);
              }
            }
            else {
              *(undefined *)((int)puVar6 + 0x323) = 1;
              dVar13 = (double)FUN_8003042c((double)FLOAT_803e3840,dVar14,param_3,param_4,param_5,
                                            param_6,param_7,param_8,puVar3,(uint)(byte)puVar11[0x20]
                                            ,0,puVar7,puVar10,in_r8,in_r9,in_r10);
            }
          }
          else {
            *(undefined *)((int)puVar6 + 0x323) = 1;
            dVar13 = (double)FUN_8003042c((double)FLOAT_803e3840,dVar14,param_3,param_4,param_5,
                                          param_6,param_7,param_8,puVar3,(uint)(byte)puVar11[0x2c],0
                                          ,puVar7,puVar10,in_r8,in_r9,in_r10);
          }
        }
        else {
          dVar13 = (double)FUN_8014d504((double)*(float *)(puVar9 + iVar4),dVar14,param_3,param_4,
                                        param_5,param_6,param_7,param_8,(int)puVar3,(int)puVar6,
                                        (uint)(byte)puVar10[8],0,(uint)(byte)puVar10[10],in_r8,in_r9
                                        ,in_r10);
          *(byte *)((int)puVar6 + 0x33d) = *(byte *)((int)puVar6 + 0x33d) | 8;
        }
      }
      else {
        iVar4 = (uint)*(byte *)((int)puVar6 + 0x33f) * 0x10;
        dVar13 = (double)FUN_8014d504((double)*(float *)(puVar10 + iVar4),dVar14,param_3,param_4,
                                      param_5,param_6,param_7,param_8,(int)puVar3,(int)puVar6,
                                      (uint)(byte)puVar10[iVar4 + 8],0,
                                      *(uint *)(puVar10 + iVar4 + 4) & 0xff,in_r8,in_r9,in_r10);
        *(char *)(puVar6 + 0xcf) =
             (char)*(undefined4 *)(puVar10 + (uint)*(byte *)((int)puVar6 + 0x33f) * 0x10 + 0xc);
        *(byte *)(puVar3 + 0x72) = *(byte *)(puVar6 + 0xcf) & 1;
        *(undefined *)((int)puVar6 + 0x33f) =
             puVar10[(uint)*(byte *)((int)puVar6 + 0x33f) * 0x10 + 9];
      }
    }
    if (((*(byte *)((int)puVar6 + 0x323) & 8) == 0) &&
       ((*(byte *)((int)puVar6 + 0x33d) & 0x10) == 0)) {
      dVar14 = (double)pfVar8[0x1c];
      dVar13 = (double)FUN_8014d3f4((short *)puVar3,puVar6,0xf,0);
    }
  }
  FUN_80158188(dVar13,dVar14,param_3,param_4,param_5,param_6,param_7,param_8);
LAB_801590b8:
  FUN_80286884();
  return;
}

