// Function: FUN_8002f6cc
// Entry: 8002f6cc
// Size: 1140 bytes

undefined4 FUN_8002f6cc(double param_1,int param_2,float *param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  short sVar6;
  float fVar7;
  float fVar8;
  bool bVar9;
  uint uVar10;
  uint uVar11;
  int *piVar12;
  int iVar13;
  float *pfVar14;
  float *pfVar15;
  float *pfVar16;
  int iVar17;
  int iVar18;
  double in_f6;
  double in_f7;
  double in_f8;
  undefined8 local_20;
  
  piVar12 = *(int **)(*(int *)(param_2 + 0x7c) + *(char *)(param_2 + 0xad) * 4);
  iVar17 = *piVar12;
  if (*(short *)(iVar17 + 0xec) != 0) {
    iVar18 = piVar12[0xb];
    fVar5 = *(float *)(param_2 + 8);
    pfVar15 = (float *)0x0;
    if (*(ushort *)(iVar18 + 0x5a) != 0) {
      in_f7 = (double)((float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar18 + 0x5a)) -
                              DOUBLE_803df568) / FLOAT_803df574);
      in_f8 = (double)(float)((double)FLOAT_803df560 - in_f7);
      if ((*(ushort *)(iVar17 + 2) & 0x40) == 0) {
        iVar13 = *(int *)(*(int *)(iVar17 + 100) + (uint)*(ushort *)(iVar18 + 0x48) * 4);
      }
      else {
        iVar13 = *(int *)(iVar18 + (uint)*(ushort *)(iVar18 + 0x48) * 4 + 0x24) + 0x80;
      }
      if (*(short *)(iVar13 + 4) != 0) {
        pfVar16 = (float *)(iVar13 + *(short *)(iVar13 + 4));
        in_f6 = (double)(*pfVar16 * fVar5);
        pfVar15 = (float *)((int)pfVar16 + 6);
        if (((*(short *)pfVar15 == 0) && (pfVar15 = pfVar16 + 2, *(short *)pfVar15 == 0)) &&
           (pfVar15 = (float *)((int)pfVar16 + 10), *(short *)pfVar15 == 0)) {
          pfVar15 = (float *)0x0;
        }
        if (pfVar15 != (float *)0x0) {
          pfVar15 = (float *)((int)pfVar15 + 2);
        }
      }
    }
    if ((*(ushort *)(iVar17 + 2) & 0x40) == 0) {
      iVar17 = *(int *)(*(int *)(iVar17 + 100) + (uint)*(ushort *)(iVar18 + 0x44) * 4);
    }
    else {
      iVar17 = *(int *)(iVar18 + (uint)*(ushort *)(iVar18 + 0x44) * 4 + 0x1c) + 0x80;
    }
    if (*(short *)(iVar17 + 4) != 0) {
      pfVar16 = (float *)(iVar17 + *(short *)(iVar17 + 4));
      fVar7 = *pfVar16 * fVar5;
      uVar10 = (int)*(short *)(pfVar16 + 1) - 1;
      pfVar14 = (float *)((int)pfVar16 + 6);
      if ((*(short *)pfVar14 == 0) && (pfVar14 = pfVar16 + 2, *(short *)pfVar14 == 0)) {
        pfVar14 = (float *)((int)pfVar16 + 10);
      }
      if (*(short *)pfVar14 != 0) {
        sVar6 = *(short *)((int)pfVar14 + uVar10 * 2 + 2);
        if (sVar6 < 0) {
          fVar7 = -fVar7;
        }
        if (sVar6 != 0) {
          fVar4 = (float)((double)CONCAT44(0x43300000,uVar10 ^ 0x80000000) - DOUBLE_803df580);
          fVar8 = FLOAT_803df560 / fVar4;
          fVar4 = fVar4 * *(float *)(param_2 + 0x98);
          uVar11 = (uint)fVar4;
          fVar4 = fVar4 - (float)((double)CONCAT44(0x43300000,uVar11 ^ 0x80000000) - DOUBLE_803df580
                                 );
          if (pfVar15 == (float *)0x0) {
            fVar1 = fVar7 * (float)((double)CONCAT44(0x43300000,
                                                     (int)*(short *)((int)pfVar14 + uVar11 * 2 + 2)
                                                     ^ 0x80000000) - DOUBLE_803df580);
            fVar2 = fVar7 * (float)((double)CONCAT44(0x43300000,
                                                     (int)*(short *)((int)pfVar14 + uVar11 * 2 + 4)
                                                     ^ 0x80000000) - DOUBLE_803df580);
          }
          else {
            if (*(short *)((int)pfVar15 + uVar10 * 2) < 0) {
              in_f6 = -in_f6;
            }
            iVar17 = uVar11 * 2;
            local_20 = (double)CONCAT44(0x43300000,
                                        (int)*(short *)((int)pfVar15 + iVar17) ^ 0x80000000);
            fVar1 = (float)(in_f6 * (double)(float)(in_f7 * (double)(float)(local_20 -
                                                                           DOUBLE_803df580)) +
                           (double)(fVar7 * (float)(in_f8 * (double)(float)((double)CONCAT44(
                                                  0x43300000,
                                                  (int)*(short *)((int)pfVar14 + iVar17 + 2) ^
                                                  0x80000000) - DOUBLE_803df580))));
            fVar2 = (float)(in_f6 * (double)(float)(in_f7 * (double)(float)((double)CONCAT44(
                                                  0x43300000,
                                                  (int)*(short *)((int)pfVar15 + iVar17 + 2) ^
                                                  0x80000000) - DOUBLE_803df580)) +
                           (double)(fVar7 * (float)(in_f8 * (double)(float)((double)CONCAT44(
                                                  0x43300000,
                                                  (int)*(short *)((int)pfVar14 + iVar17 + 4) ^
                                                  0x80000000) - DOUBLE_803df580))));
          }
          fVar5 = (float)(param_1 * (double)(fVar5 / *(float *)(*(int *)(param_2 + 0x50) + 4))) +
                  fVar4 * (fVar2 - fVar1) + fVar1;
          fVar4 = -(fVar8 * fVar4 - fVar8);
          bVar9 = false;
          do {
            if (fVar2 <= fVar5) {
              uVar11 = uVar11 + 1;
              if ((int)uVar10 <= (int)uVar11) {
                uVar11 = 0;
              }
              if (pfVar15 == (float *)0x0) {
                fVar3 = fVar7 * ((float)((double)CONCAT44(0x43300000,
                                                          (int)*(short *)((int)pfVar14 +
                                                                         uVar11 * 2 + 4) ^
                                                          0x80000000) - DOUBLE_803df580) -
                                (float)((double)CONCAT44(0x43300000,
                                                         (int)*(short *)((int)pfVar14 +
                                                                        uVar11 * 2 + 2) ^ 0x80000000
                                                        ) - DOUBLE_803df580));
              }
              else {
                iVar17 = uVar11 * 2;
                local_20 = (double)CONCAT44(0x43300000,
                                            (int)((short *)((int)pfVar15 + iVar17))[1] ^ 0x80000000)
                ;
                fVar3 = (float)((double)(fVar7 * ((float)((double)CONCAT44(0x43300000,
                                                                           (int)*(short *)((int)
                                                  pfVar14 + iVar17 + 4) ^ 0x80000000) -
                                                  DOUBLE_803df580) -
                                                 (float)((double)CONCAT44(0x43300000,
                                                                          (int)*(short *)((int)
                                                  pfVar14 + iVar17 + 2) ^ 0x80000000) -
                                                  DOUBLE_803df580))) * in_f8 +
                               (double)(float)((double)(float)(in_f6 * (double)((float)(local_20 -
                                                                                                                                                                              
                                                  DOUBLE_803df580) -
                                                  (float)((double)CONCAT44(0x43300000,
                                                                           (int)*(short *)((int)
                                                  pfVar15 + iVar17) ^ 0x80000000) - DOUBLE_803df580)
                                                  )) * in_f7));
              }
              fVar4 = fVar4 + fVar8;
              fVar1 = fVar2;
              fVar2 = fVar2 + fVar3;
            }
            else {
              fVar4 = fVar4 - (fVar8 * (fVar2 - fVar5)) / (fVar2 - fVar1);
              bVar9 = true;
            }
          } while (!bVar9);
          if (param_3 != (float *)0x0) {
            *param_3 = fVar4;
          }
          return 1;
        }
        return 0;
      }
    }
  }
  return 0;
}

