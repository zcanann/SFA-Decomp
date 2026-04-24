// Function: FUN_801b0e3c
// Entry: 801b0e3c
// Size: 1304 bytes

/* WARNING: Removing unreachable block (ram,0x801b1324) */
/* WARNING: Removing unreachable block (ram,0x801b132c) */

void FUN_801b0e3c(int param_1)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  byte bVar5;
  short sVar6;
  int iVar7;
  int iVar8;
  short sVar9;
  uint uVar10;
  int *piVar11;
  undefined4 uVar12;
  double dVar13;
  double dVar14;
  undefined8 in_f30;
  double dVar15;
  undefined8 in_f31;
  double dVar16;
  short local_c8;
  short local_c4;
  short local_c2;
  double local_50;
  double local_40;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar12 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  piVar11 = *(int **)(param_1 + 0xb8);
  iVar7 = FUN_8002b9ec();
  bVar5 = DAT_803db410;
  if (*piVar11 == 0) {
    FUN_8002cbc4(param_1);
  }
  else {
    uVar10 = (uint)DAT_803db410;
    sVar6 = (short)piVar11[2];
    iVar8 = (int)DAT_803dbee8;
    if ((int)sVar6 < iVar8 + -1) {
      local_c8 = sVar6 + -1;
      if (local_c8 < 0) {
        local_c8 = 0;
      }
      sVar9 = (short)(iVar8 + -1);
      local_c4 = sVar6 + 1;
      if (iVar8 <= (short)(sVar6 + 1)) {
        local_c4 = sVar9;
      }
      local_c2 = sVar6 + 2;
      if (iVar8 <= (short)(sVar6 + 2)) {
        local_c2 = sVar9;
      }
      iVar8 = (short)(sVar6 * 3) * 2;
      fVar1 = (float)((double)CONCAT44(0x43300000,
                                       (int)*(short *)(&DAT_80323bc0 + iVar8) ^ 0x80000000) -
                     DOUBLE_803e4858) * FLOAT_803e484c;
      dVar15 = (double)((float)((double)CONCAT44(0x43300000,
                                                 (int)*(short *)(&DAT_80323bc2 + iVar8) ^ 0x80000000
                                                ) - DOUBLE_803e4858) * FLOAT_803e484c);
      fVar2 = (float)((double)CONCAT44(0x43300000,
                                       (int)*(short *)(&DAT_80323bc4 + iVar8) ^ 0x80000000) -
                     DOUBLE_803e4858) * FLOAT_803e484c;
      iVar8 = (short)(local_c4 * 3) * 2;
      fVar3 = (float)((double)CONCAT44(0x43300000,
                                       (int)*(short *)(&DAT_80323bc0 + iVar8) ^ 0x80000000) -
                     DOUBLE_803e4858) * FLOAT_803e484c;
      dVar16 = (double)((float)((double)CONCAT44(0x43300000,
                                                 (int)*(short *)(&DAT_80323bc2 + iVar8) ^ 0x80000000
                                                ) - DOUBLE_803e4858) * FLOAT_803e484c);
      local_50 = (double)CONCAT44(0x43300000,(int)*(short *)(&DAT_80323bc4 + iVar8) ^ 0x80000000);
      fVar4 = (float)(local_50 - DOUBLE_803e4858) * FLOAT_803e484c;
      local_40 = (double)CONCAT44(0x43300000,
                                  (int)*(short *)(&DAT_80323bc2 + (short)(local_c2 * 3) * 2) ^
                                  0x80000000);
      if ((((float)(dVar16 - (double)((float)(local_40 - DOUBLE_803e4858) * FLOAT_803e484c)) <=
            FLOAT_803e4850) &&
          ((float)(dVar15 - (double)((float)((double)CONCAT44(0x43300000,
                                                              (int)*(short *)(&DAT_80323bc2 +
                                                                             (short)(local_c8 * 3) *
                                                                             2) ^ 0x80000000) -
                                            DOUBLE_803e4858) * FLOAT_803e484c)) <= FLOAT_803e4850))
         && (*(char *)(piVar11 + 3) < '\x01')) {
        FUN_802931a0((double)(*(float *)(param_1 + 0x2c) * *(float *)(param_1 + 0x2c) +
                             *(float *)(param_1 + 0x24) * *(float *)(param_1 + 0x24) +
                             *(float *)(param_1 + 0x28) * *(float *)(param_1 + 0x28)));
        if ((*(ushort *)(iVar7 + 0xb0) & 0x1000) == 0) {
          FUN_8000bb18(param_1,0x1fb);
        }
        *(undefined *)(piVar11 + 3) = 0x1e;
      }
      dVar14 = (double)fVar1;
      dVar13 = (double)FLOAT_803e4850;
      *(float *)(param_1 + 0xc) = (float)(dVar13 * (double)(float)((double)fVar3 - dVar14) + dVar14)
      ;
      *(float *)(param_1 + 0x10) = (float)(dVar13 * (double)(float)(dVar16 - dVar15) + dVar15);
      dVar15 = (double)fVar2;
      *(float *)(param_1 + 0x14) =
           (float)(dVar13 * (double)(float)((double)fVar4 - dVar15) + dVar15);
      *(float *)(param_1 + 0xc) = *(float *)(param_1 + 0xc) + *(float *)(*piVar11 + 0xc);
      *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) + *(float *)(*piVar11 + 0x10);
      *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) + *(float *)(*piVar11 + 0x14);
      *(float *)(param_1 + 0x24) =
           FLOAT_803db418 * (*(float *)(param_1 + 0xc) - *(float *)(param_1 + 0x80));
      *(float *)(param_1 + 0x28) =
           FLOAT_803db418 * (*(float *)(param_1 + 0x10) - *(float *)(param_1 + 0x84));
      *(float *)(param_1 + 0x2c) =
           FLOAT_803db418 * (*(float *)(param_1 + 0x14) - *(float *)(param_1 + 0x88));
      piVar11[2] = piVar11[2] + uVar10;
      if ('\0' < *(char *)(piVar11 + 3)) {
        *(byte *)(piVar11 + 3) = *(char *)(piVar11 + 3) - bVar5;
      }
      dVar15 = DOUBLE_803e4858;
      fVar1 = FLOAT_803e4854;
      *(short *)(param_1 + 2) =
           (short)(int)-(FLOAT_803e4854 * -*(float *)(param_1 + 0x2c) -
                        (float)((double)CONCAT44(0x43300000,
                                                 (int)*(short *)(param_1 + 2) ^ 0x80000000) -
                               DOUBLE_803e4858));
      *(short *)(param_1 + 4) =
           (short)(int)-(fVar1 * *(float *)(param_1 + 0x24) -
                        (float)((double)CONCAT44(0x43300000,
                                                 (int)*(short *)(param_1 + 4) ^ 0x80000000) - dVar15
                               ));
      iVar7 = *(int *)(param_1 + 0x54);
      if (iVar7 != 0) {
        *(ushort *)(iVar7 + 0x60) = *(ushort *)(iVar7 + 0x60) | 1;
        *(undefined *)(iVar7 + 0x6e) = 4;
        *(undefined *)(iVar7 + 0x6f) = 2;
        *(undefined4 *)(iVar7 + 0x48) = 0x10;
        *(undefined4 *)(iVar7 + 0x4c) = 0x10;
      }
    }
    else {
      FUN_8002cbc4(param_1);
    }
  }
  __psq_l0(auStack8,uVar12);
  __psq_l1(auStack8,uVar12);
  __psq_l0(auStack24,uVar12);
  __psq_l1(auStack24,uVar12);
  return;
}

