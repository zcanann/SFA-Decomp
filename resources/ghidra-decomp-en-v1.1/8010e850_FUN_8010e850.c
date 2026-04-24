// Function: FUN_8010e850
// Entry: 8010e850
// Size: 3212 bytes

/* WARNING: Removing unreachable block (ram,0x8010f4bc) */
/* WARNING: Removing unreachable block (ram,0x8010f4b4) */
/* WARNING: Removing unreachable block (ram,0x8010f4ac) */
/* WARNING: Removing unreachable block (ram,0x8010f4a4) */
/* WARNING: Removing unreachable block (ram,0x8010e878) */
/* WARNING: Removing unreachable block (ram,0x8010e870) */
/* WARNING: Removing unreachable block (ram,0x8010e868) */
/* WARNING: Removing unreachable block (ram,0x8010e860) */
/* WARNING: Removing unreachable block (ram,0x8010e8e0) */

void FUN_8010e850(void)

{
  float fVar1;
  float fVar2;
  float fVar3;
  short sVar4;
  short *psVar5;
  int iVar6;
  short *psVar7;
  uint uVar8;
  int iVar9;
  char cVar11;
  char cVar12;
  short *psVar10;
  short sVar13;
  int iVar14;
  double dVar15;
  double dVar16;
  double dVar17;
  double dVar18;
  double dVar19;
  
  psVar5 = (short *)FUN_80286838();
  dVar18 = (double)FLOAT_803e26a8;
  iVar14 = *(int *)(psVar5 + 0x52);
  iVar6 = FUN_8002e1ac(0x42fff);
  psVar7 = (short *)FUN_8002e1ac(0x4325b);
  uVar8 = FUN_80014f14(0);
  FUN_80014e9c(0);
  if (*(char *)(DAT_803de200 + 2) == '\x01') {
    psVar10 = (short *)FUN_8002e1ac(0x43077);
    if (*(char *)((int)DAT_803de200 + 9) == *(char *)(DAT_803de200 + 2)) {
      if ((*(char *)((int)DAT_803de200 + 0x15) < '\0') &&
         (iVar6 = (**(code **)(*DAT_803dd6cc + 0x14))(), iVar6 != 0)) {
        FUN_8012e0f4('\x01');
        (**(code **)(*DAT_803dd6cc + 0xc))(0xc,1);
        *(byte *)((int)DAT_803de200 + 0x15) = *(byte *)((int)DAT_803de200 + 0x15) & 0x7f;
        iVar6 = FUN_8002e1ac(0x43077);
        *(undefined *)(*(int *)(iVar6 + 0xb8) + 0x27d) = 1;
      }
      if (-1 < *(char *)((int)DAT_803de200 + 0x15)) {
        *(short *)((int)DAT_803de200 + 10) = *(short *)((int)DAT_803de200 + 10) + -1;
        if (*(short *)((int)DAT_803de200 + 10) < 1) {
          *(undefined2 *)((int)DAT_803de200 + 10) = 1;
        }
        iVar6 = FUN_80021884();
        sVar4 = (-0x308f - (short)iVar6) - *psVar5;
        if (0x8000 < sVar4) {
          sVar4 = sVar4 + 1;
        }
        if (sVar4 < -0x8000) {
          sVar4 = sVar4 + -1;
        }
        *psVar5 = *psVar5 + sVar4 / *(short *)((int)DAT_803de200 + 10);
        sVar4 = -psVar5[1] + 2000;
        if (0x8000 < sVar4) {
          sVar4 = -psVar5[1] + 0x7d1;
        }
        if (sVar4 < -0x8000) {
          sVar4 = sVar4 + -1;
        }
        psVar5[1] = psVar5[1] + sVar4 / *(short *)((int)DAT_803de200 + 10);
        dVar19 = (double)FUN_80294964();
        dVar19 = -dVar19;
        dVar15 = (double)FUN_802945e0();
        dVar17 = (double)FUN_80294964();
        dVar16 = (double)FUN_802945e0();
        dVar18 = DOUBLE_803e26f0;
        dVar17 = (double)(float)((double)FLOAT_803e26d8 * dVar17);
        fVar2 = FLOAT_803e26dc +
                *(float *)(iVar14 + 0x1c) + (float)((double)FLOAT_803e26d8 * dVar16);
        fVar1 = *(float *)(iVar14 + 0x20);
        *(float *)(psVar5 + 0xc) =
             *(float *)(psVar5 + 0xc) -
             (*(float *)(psVar5 + 0xc) - (*(float *)(iVar14 + 0x18) + (float)(dVar17 * dVar15))) /
             (float)((double)CONCAT44(0x43300000,
                                      (int)*(short *)((int)DAT_803de200 + 10) ^ 0x80000000) -
                    DOUBLE_803e26f0);
        *(float *)(psVar5 + 0xe) =
             *(float *)(psVar5 + 0xe) -
             (*(float *)(psVar5 + 0xe) - fVar2) /
             (float)((double)CONCAT44(0x43300000,
                                      (int)*(short *)((int)DAT_803de200 + 10) ^ 0x80000000) - dVar18
                    );
        *(float *)(psVar5 + 0x10) =
             *(float *)(psVar5 + 0x10) -
             (*(float *)(psVar5 + 0x10) - (fVar1 + (float)(dVar17 * dVar19))) /
             (float)((double)CONCAT44(0x43300000,
                                      (int)*(short *)((int)DAT_803de200 + 10) ^ 0x80000000) - dVar18
                    );
        sVar4 = *psVar5;
        sVar13 = sVar4 + 5000;
        uVar8 = FUN_8005cf2c();
        if (uVar8 != 0) {
          sVar13 = sVar4 + 0x189c;
        }
        dVar18 = (double)FUN_80294964();
        dVar19 = (double)FUN_802945e0();
        dVar15 = (double)FLOAT_803e26e0;
        *(float *)(psVar10 + 6) = (float)(dVar15 * -dVar19 + (double)*(float *)(psVar5 + 0xc));
        *(float *)(psVar10 + 8) =
             *(float *)(psVar5 + 0xe) +
             *(float *)(&DAT_8031aa48 + *(char *)((int)psVar10 + 0xad) * 4);
        *(float *)(psVar10 + 10) = (float)(dVar15 * dVar18 + (double)*(float *)(psVar5 + 0x10));
        *psVar10 = -3000 - sVar13;
      }
    }
    else {
      (**(code **)(*DAT_803dd6cc + 8))(0xc,1);
      *(undefined2 *)((int)DAT_803de200 + 10) = 2;
      *(byte *)((int)DAT_803de200 + 0x15) = *(byte *)((int)DAT_803de200 + 0x15) & 0x7f | 0x80;
    }
  }
  else if (*(char *)(DAT_803de200 + 2) == '\0') {
    if (*(char *)((int)DAT_803de200 + 9) == '\0') {
      if ((*(char *)((int)DAT_803de200 + 0x15) < '\0') &&
         (iVar9 = (**(code **)(*DAT_803dd6cc + 0x14))(), iVar9 != 0)) {
        FUN_8012e0f4('\0');
        (**(code **)(*DAT_803dd6cc + 0xc))(0xc,1);
        *(byte *)((int)DAT_803de200 + 0x15) = *(byte *)((int)DAT_803de200 + 0x15) & 0x7f;
        iVar9 = FUN_8002e1ac(0x43077);
        *(undefined *)(*(int *)(iVar9 + 0xb8) + 0x27d) = 0;
      }
      if (-1 < *(char *)((int)DAT_803de200 + 0x15)) {
        *(short *)((int)DAT_803de200 + 10) = *(short *)((int)DAT_803de200 + 10) + -1;
        if (*(short *)((int)DAT_803de200 + 10) < 1) {
          *(undefined2 *)((int)DAT_803de200 + 10) = 1;
        }
        if ((uVar8 & 8) != 0) {
          dVar18 = (double)(FLOAT_803e26ac * *DAT_803de200);
        }
        if ((uVar8 & 4) != 0) {
          dVar18 = (double)(FLOAT_803e26b0 * *DAT_803de200);
        }
        dVar19 = dVar18;
        if (dVar18 < (double)FLOAT_803e26a8) {
          dVar19 = -dVar18;
        }
        dVar17 = (double)DAT_803de200[1];
        dVar15 = dVar17;
        if (dVar17 < (double)FLOAT_803e26a8) {
          dVar15 = -dVar17;
        }
        fVar1 = FLOAT_803e26b8;
        if (dVar19 < dVar15) {
          fVar1 = FLOAT_803e26b4;
        }
        DAT_803de200[1] = fVar1 * (float)(dVar18 - dVar17) + DAT_803de200[1];
        *DAT_803de200 = *DAT_803de200 + DAT_803de200[1];
        if (*DAT_803de200 < FLOAT_803e26bc) {
          *DAT_803de200 = FLOAT_803e26bc;
        }
        if (FLOAT_803e26c0 < *DAT_803de200) {
          *DAT_803de200 = FLOAT_803e26c0;
        }
        cVar11 = FUN_80014c44(0);
        cVar12 = FUN_80014bf0(0);
        if (*(char *)(DAT_803de200 + 5) != '\0') {
          iVar9 = FUN_8002e1ac((int)DAT_803de200[4]);
          dVar18 = (double)(*(float *)(iVar9 + 0x18) - *(float *)(iVar6 + 0x18));
          dVar19 = (double)(*(float *)(iVar9 + 0x20) - *(float *)(iVar6 + 0x20));
          iVar6 = FUN_80021884();
          *(short *)(DAT_803de200 + 3) = -0x8000 - (short)iVar6;
          sVar4 = *(short *)(DAT_803de200 + 3) - *psVar5;
          if (0x8000 < sVar4) {
            sVar4 = sVar4 + 1;
          }
          if (sVar4 < -0x8000) {
            sVar4 = sVar4 + -1;
          }
          *psVar5 = *psVar5 + (short)((int)sVar4 / (int)(uint)*(byte *)(DAT_803de200 + 5));
          FUN_80293900((double)(float)(dVar18 * dVar18 + (double)(float)(dVar19 * dVar19)));
          iVar6 = FUN_80021884();
          *(short *)(DAT_803de200 + 3) = 0x47d0 - (short)iVar6;
          sVar4 = *(short *)(DAT_803de200 + 3) - psVar5[1];
          if (0x8000 < sVar4) {
            sVar4 = sVar4 + 1;
          }
          if (sVar4 < -0x8000) {
            sVar4 = sVar4 + -1;
          }
          psVar5[1] = psVar5[1] + (short)((int)sVar4 / (int)(uint)*(byte *)(DAT_803de200 + 5));
          *DAT_803de200 =
               *DAT_803de200 +
               (float)((double)CONCAT44(0x43300000,
                                        (int)(short)(int)(FLOAT_803e26c4 - *DAT_803de200) /
                                        (int)(uint)*(byte *)(DAT_803de200 + 5) ^ 0x80000000) -
                      DOUBLE_803e26f0);
          *(char *)(DAT_803de200 + 5) = *(char *)(DAT_803de200 + 5) + -1;
        }
        *psVar5 = *psVar5 + cVar11 * 3;
        psVar5[1] = psVar5[1] + cVar12 * 3;
        if (12000 < psVar5[1]) {
          psVar5[1] = 12000;
        }
        if (psVar5[1] < -12000) {
          psVar5[1] = -12000;
        }
        dVar19 = (double)FUN_80294964();
        dVar19 = -dVar19;
        dVar15 = (double)FUN_802945e0();
        dVar17 = (double)FUN_80294964();
        dVar16 = (double)FUN_802945e0();
        dVar18 = DOUBLE_803e26f0;
        fVar1 = *DAT_803de200;
        dVar17 = (double)(float)((double)fVar1 * dVar17);
        fVar3 = FLOAT_803e26d0 + *(float *)(iVar14 + 0x1c);
        fVar2 = *(float *)(iVar14 + 0x20);
        *(float *)(psVar5 + 0xc) =
             *(float *)(psVar5 + 0xc) -
             (*(float *)(psVar5 + 0xc) - (*(float *)(iVar14 + 0x18) + (float)(dVar17 * dVar15))) /
             (float)((double)CONCAT44(0x43300000,
                                      (int)*(short *)((int)DAT_803de200 + 10) ^ 0x80000000) -
                    DOUBLE_803e26f0);
        *(float *)(psVar5 + 0xe) =
             *(float *)(psVar5 + 0xe) -
             (*(float *)(psVar5 + 0xe) - (fVar3 + (float)((double)fVar1 * dVar16))) /
             (float)((double)CONCAT44(0x43300000,
                                      (int)*(short *)((int)DAT_803de200 + 10) ^ 0x80000000) - dVar18
                    );
        *(float *)(psVar5 + 0x10) =
             *(float *)(psVar5 + 0x10) -
             (*(float *)(psVar5 + 0x10) - (fVar2 + (float)(dVar17 * dVar19))) /
             (float)((double)CONCAT44(0x43300000,
                                      (int)*(short *)((int)DAT_803de200 + 10) ^ 0x80000000) - dVar18
                    );
      }
    }
    else {
      *(undefined *)(DAT_803de200 + 5) = 1;
      (**(code **)(*DAT_803dd6cc + 8))(0xc,1);
      *(undefined2 *)((int)DAT_803de200 + 10) = 2;
      *(byte *)((int)DAT_803de200 + 0x15) = *(byte *)((int)DAT_803de200 + 0x15) & 0x7f | 0x80;
    }
  }
  *(undefined *)((int)DAT_803de200 + 9) = *(undefined *)(DAT_803de200 + 2);
  psVar10 = (short *)FUN_8002e1ac(0x431dc);
  dVar18 = (double)(*(float *)(psVar10 + 0xc) - *(float *)(psVar5 + 0xc));
  dVar19 = (double)(*(float *)(psVar10 + 0x10) - *(float *)(psVar5 + 0x10));
  iVar6 = FUN_80021884();
  *psVar10 = (short)iVar6 + -0x8000;
  FUN_80293900((double)(float)(dVar18 * dVar18 + (double)(float)(dVar19 * dVar19)));
  iVar6 = FUN_80021884();
  psVar10[1] = -0x8000 - (short)iVar6;
  *(float *)(psVar10 + 4) = FLOAT_803e26e4 + FLOAT_803e26e8 / *DAT_803de200;
  *psVar7 = *psVar10;
  psVar7[1] = psVar10[1];
  *(undefined4 *)(psVar7 + 4) = *(undefined4 *)(psVar10 + 4);
  if (((short)(*psVar7 + -0x2198) < -0x1fff) || (0x1fff < (short)(*psVar7 + -0x2198))) {
    *(undefined *)(psVar7 + 0x1b) = 0;
  }
  else {
    dVar18 = (double)FUN_80294964();
    dVar19 = (double)FUN_80294964();
    fVar1 = FLOAT_803e26a8;
    if (FLOAT_803e26a8 <= FLOAT_803e26ec * (float)(dVar19 * dVar18)) {
      dVar18 = (double)FUN_80294964();
      dVar19 = (double)FUN_80294964();
      fVar1 = FLOAT_803e26ec * (float)(dVar19 * dVar18);
    }
    *(char *)(psVar7 + 0x1b) = (char)(int)fVar1;
  }
  FUN_8000e054((double)*(float *)(psVar5 + 0xc),(double)*(float *)(psVar5 + 0xe),
               (double)*(float *)(psVar5 + 0x10),(float *)(psVar5 + 6),(float *)(psVar5 + 8),
               (float *)(psVar5 + 10),*(int *)(psVar5 + 0x18));
  FUN_80286884();
  return;
}

