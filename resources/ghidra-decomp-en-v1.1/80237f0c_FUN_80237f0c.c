// Function: FUN_80237f0c
// Entry: 80237f0c
// Size: 1960 bytes

/* WARNING: Removing unreachable block (ram,0x80238694) */
/* WARNING: Removing unreachable block (ram,0x8023868c) */
/* WARNING: Removing unreachable block (ram,0x80238684) */
/* WARNING: Removing unreachable block (ram,0x8023867c) */
/* WARNING: Removing unreachable block (ram,0x80238674) */
/* WARNING: Removing unreachable block (ram,0x8023866c) */
/* WARNING: Removing unreachable block (ram,0x80237f44) */
/* WARNING: Removing unreachable block (ram,0x80237f3c) */
/* WARNING: Removing unreachable block (ram,0x80237f34) */
/* WARNING: Removing unreachable block (ram,0x80237f2c) */
/* WARNING: Removing unreachable block (ram,0x80237f24) */
/* WARNING: Removing unreachable block (ram,0x80237f1c) */

void FUN_80237f0c(void)

{
  bool bVar1;
  byte bVar2;
  float fVar3;
  short sVar4;
  uint uVar5;
  short *psVar6;
  uint uVar7;
  int iVar8;
  uint uVar9;
  int iVar10;
  int iVar11;
  char in_r8;
  byte bVar12;
  int iVar13;
  float *pfVar14;
  double in_f26;
  double dVar15;
  double in_f27;
  double dVar16;
  double in_f28;
  double dVar17;
  double in_f29;
  double dVar18;
  double in_f30;
  double dVar19;
  double in_f31;
  double dVar20;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined auStack_d8 [8];
  float local_d0;
  float local_c8;
  undefined8 local_c0;
  undefined8 local_b8;
  undefined8 local_b0;
  undefined8 local_a8;
  undefined4 local_a0;
  uint uStack_9c;
  undefined8 local_98;
  float local_58;
  float fStack_54;
  float local_48;
  float fStack_44;
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
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  local_58 = (float)in_f26;
  fStack_54 = (float)in_ps26_1;
  psVar6 = (short *)FUN_80286824();
  pfVar14 = *(float **)(psVar6 + 0x5c);
  iVar13 = *(int *)(psVar6 + 0x26);
  if (in_r8 != '\0') {
    uVar7 = FUN_80020800();
    uVar7 = uVar7 & 0xff;
    fVar3 = FLOAT_803dc074;
    if (uVar7 != 0) {
      fVar3 = FLOAT_803e8068;
    }
    dVar16 = (double)fVar3;
    if ((*(char *)((int)pfVar14 + 0x26) < '\0') || (*pfVar14 != FLOAT_803e8068)) {
      sVar4 = psVar6[0x23];
      if ((sVar4 == 0x835) || (sVar4 == 0x838)) {
        iVar8 = FUN_800395a4((int)psVar6,0);
        if (iVar8 != 0) {
          bVar1 = *(short *)(iVar13 + 0x1c) != 0;
          uVar5 = (uint)bVar1;
          if (((int)*(short *)(iVar13 + 0x1e) != 0xffffffff) &&
             (uVar9 = FUN_80020078((int)*(short *)(iVar13 + 0x1e)), uVar9 != 0)) {
            uVar5 = countLeadingZeros((uint)bVar1);
            uVar5 = uVar5 >> 5 & 0xff;
          }
          if (uVar5 == 0) {
            local_b8 = (double)(longlong)(int)((double)FLOAT_803e806c * dVar16);
            *(short *)(iVar8 + 8) =
                 *(short *)(iVar8 + 8) + (short)(int)((double)FLOAT_803e806c * dVar16);
            if (9999 < *(short *)(iVar8 + 8)) {
              *(short *)(iVar8 + 8) = *(short *)(iVar8 + 8) + -10000;
            }
          }
          else {
            local_c0 = (double)(longlong)(int)((double)FLOAT_803e806c * dVar16);
            *(short *)(iVar8 + 8) =
                 *(short *)(iVar8 + 8) - (short)(int)((double)FLOAT_803e806c * dVar16);
            local_b8 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar8 + 8) ^ 0x80000000);
            if ((float)(local_b8 - DOUBLE_803e8088) <= FLOAT_803e8068) {
              *(short *)(iVar8 + 8) = *(short *)(iVar8 + 8) + 10000;
            }
          }
        }
        pfVar14[1] = (float)((double)pfVar14[1] - dVar16);
        fVar3 = FLOAT_803e8068;
        if ((pfVar14[1] <= FLOAT_803e8068) && (uVar7 == 0)) {
          pfVar14[1] = FLOAT_803e8070;
          local_b8 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar13 + 0x1a) ^ 0x80000000);
          local_d0 = ((float)(local_b8 - DOUBLE_803e8088) / FLOAT_803e8074) *
                     *(float *)(psVar6 + 4) * *pfVar14;
          local_c8 = fVar3;
          (**(code **)(*DAT_803dd708 + 8))(psVar6,0x7f7,auStack_d8,2,0xffffffff,0);
        }
        iVar8 = FUN_8002b660((int)psVar6);
        dVar18 = (double)*(float *)(psVar6 + 4);
        bVar2 = *(byte *)(psVar6 + 0x1b);
        sVar4 = *psVar6;
        dVar17 = (double)*(float *)(psVar6 + 8);
        dVar20 = (double)FLOAT_803e8074;
        dVar15 = DOUBLE_803e8090;
        dVar19 = DOUBLE_803e8088;
        for (bVar12 = 0; bVar12 < 2; bVar12 = bVar12 + 1) {
          uVar7 = (uint)bVar12;
          iVar11 = uVar7 * 2;
          psVar6[2] = *(short *)(&DAT_803dd07c + iVar11);
          iVar10 = iVar11 + 0x20;
          *psVar6 = *(short *)((int)pfVar14 + iVar10);
          local_b8 = (double)CONCAT44(0x43300000,
                                      (int)*(short *)(&DAT_803dd078 + iVar11) ^ 0x80000000);
          local_c0 = (double)CONCAT44(0x43300000,(int)*(short *)((int)pfVar14 + iVar10) ^ 0x80000000
                                     );
          iVar11 = (int)(dVar16 * (double)(float)(local_b8 - dVar19) +
                        (double)(float)(local_c0 - dVar19));
          local_b0 = (double)(longlong)iVar11;
          *(short *)((int)pfVar14 + iVar10) = (short)iVar11;
          local_a8 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar13 + 0x1a) ^ 0x80000000);
          *(float *)(psVar6 + 4) =
               (float)((double)(float)(local_a8 - dVar19) / dVar20) *
               *pfVar14 * (float)((double)pfVar14[uVar7 + 5] * dVar18);
          local_a0 = 0x43300000;
          iVar11 = (int)(*pfVar14 *
                        pfVar14[uVar7 + 2] *
                        (float)((double)CONCAT44(0x43300000,(uint)bVar2) - dVar15));
          local_98 = (double)(longlong)iVar11;
          *(char *)((int)psVar6 + 0x37) = (char)iVar11;
          *(ushort *)(iVar8 + 0x18) = *(ushort *)(iVar8 + 0x18) & 0xfff7;
          uStack_9c = (uint)bVar2;
          FUN_8003b9ec((int)psVar6);
        }
        *(float *)(psVar6 + 4) = (float)dVar18;
        *(byte *)(psVar6 + 0x1b) = bVar2;
        *psVar6 = sVar4;
        *(float *)(psVar6 + 8) = (float)dVar17;
      }
      else if (sVar4 == 0x83d) {
        iVar13 = FUN_800395a4((int)psVar6,0);
        if (iVar13 != 0) {
          *(short *)(iVar13 + 8) =
               *(short *)(iVar13 + 8) + (short)(int)((double)FLOAT_803e807c * dVar16);
        }
        local_98 = (double)(longlong)(int)((double)FLOAT_803e806c * dVar16);
        *psVar6 = *psVar6 + (short)(int)((double)FLOAT_803e806c * dVar16);
        if (9999 < *(short *)(iVar13 + 8)) {
          *(short *)(iVar13 + 8) = *(short *)(iVar13 + 8) + -10000;
        }
        iVar13 = FUN_8002b660((int)psVar6);
        dVar20 = (double)*(float *)(psVar6 + 4);
        bVar2 = *(byte *)(psVar6 + 0x1b);
        sVar4 = *psVar6;
        dVar18 = (double)*(float *)(psVar6 + 8);
        dVar17 = (double)FLOAT_803e8080;
        dVar15 = DOUBLE_803e8090;
        dVar19 = DOUBLE_803e8088;
        for (bVar12 = 0; bVar12 < 3; bVar12 = bVar12 + 1) {
          uVar7 = (uint)bVar12;
          iVar11 = uVar7 * 2 + 0x20;
          *psVar6 = *(short *)((int)pfVar14 + iVar11);
          local_98 = (double)CONCAT44(0x43300000,
                                      (int)*(short *)(&DAT_803dd050 + uVar7 * 2) ^ 0x80000000);
          uStack_9c = (int)*(short *)((int)pfVar14 + iVar11) ^ 0x80000000;
          local_a0 = 0x43300000;
          iVar8 = (int)(dVar16 * (double)(float)(local_98 - dVar19) +
                       (double)(float)((double)CONCAT44(0x43300000,uStack_9c) - dVar19));
          local_a8 = (double)(longlong)iVar8;
          *(short *)((int)pfVar14 + iVar11) = (short)iVar8;
          *(float *)(psVar6 + 4) = *pfVar14 * (float)((double)pfVar14[uVar7 + 5] * dVar20);
          local_b0 = (double)CONCAT44(0x43300000,(uint)bVar2);
          iVar8 = (int)(*pfVar14 * pfVar14[uVar7 + 2] * (float)(local_b0 - dVar15));
          local_b8 = (double)(longlong)iVar8;
          *(char *)((int)psVar6 + 0x37) = (char)iVar8;
          *(float *)(psVar6 + 8) =
               -(float)((double)(float)(dVar17 * (double)pfVar14[uVar7 + 5]) * (double)*pfVar14 -
                       dVar18);
          *(ushort *)(iVar13 + 0x18) = *(ushort *)(iVar13 + 0x18) & 0xfff7;
          FUN_8003b9ec((int)psVar6);
        }
        *(float *)(psVar6 + 4) = (float)dVar20;
        *(byte *)(psVar6 + 0x1b) = bVar2;
        *psVar6 = sVar4;
        *(float *)(psVar6 + 8) = (float)dVar18;
      }
      else {
        iVar13 = FUN_800395a4((int)psVar6,0);
        if (iVar13 != 0) {
          *(short *)(iVar13 + 8) =
               *(short *)(iVar13 + 8) + (short)(int)((double)FLOAT_803e807c * dVar16);
        }
        local_98 = (double)(longlong)(int)((double)FLOAT_803e806c * dVar16);
        *psVar6 = *psVar6 + (short)(int)((double)FLOAT_803e806c * dVar16);
        if (9999 < *(short *)(iVar13 + 8)) {
          *(short *)(iVar13 + 8) = *(short *)(iVar13 + 8) + -10000;
        }
        local_d0 = *(float *)(psVar6 + 4) * *pfVar14;
        if (uVar7 == 0) {
          (**(code **)(*DAT_803dd708 + 8))(psVar6,0x7c2,auStack_d8,2,0xffffffff,0);
        }
        iVar13 = FUN_8002b660((int)psVar6);
        dVar20 = (double)*(float *)(psVar6 + 4);
        bVar2 = *(byte *)(psVar6 + 0x1b);
        sVar4 = *psVar6;
        dVar18 = (double)*(float *)(psVar6 + 8);
        dVar17 = (double)FLOAT_803e8084;
        dVar15 = DOUBLE_803e8090;
        dVar19 = DOUBLE_803e8088;
        for (bVar12 = 0; bVar12 < 3; bVar12 = bVar12 + 1) {
          uVar7 = (uint)bVar12;
          iVar11 = uVar7 * 2 + 0x20;
          *psVar6 = *(short *)((int)pfVar14 + iVar11);
          local_98 = (double)CONCAT44(0x43300000,
                                      (int)*(short *)(&DAT_803dd058 + uVar7 * 2) ^ 0x80000000);
          uStack_9c = (int)*(short *)((int)pfVar14 + iVar11) ^ 0x80000000;
          local_a0 = 0x43300000;
          iVar8 = (int)(dVar16 * (double)(float)(local_98 - dVar19) +
                       (double)(float)((double)CONCAT44(0x43300000,uStack_9c) - dVar19));
          local_a8 = (double)(longlong)iVar8;
          *(short *)((int)pfVar14 + iVar11) = (short)iVar8;
          *(float *)(psVar6 + 4) = *pfVar14 * (float)((double)pfVar14[uVar7 + 5] * dVar20);
          local_b0 = (double)CONCAT44(0x43300000,(uint)bVar2);
          iVar8 = (int)(*pfVar14 * pfVar14[uVar7 + 2] * (float)(local_b0 - dVar15));
          local_b8 = (double)(longlong)iVar8;
          *(char *)((int)psVar6 + 0x37) = (char)iVar8;
          *(float *)(psVar6 + 8) =
               (float)((double)(float)(dVar17 * (double)pfVar14[uVar7 + 5]) * (double)*pfVar14 +
                      dVar18);
          *(ushort *)(iVar13 + 0x18) = *(ushort *)(iVar13 + 0x18) & 0xfff7;
          FUN_8003b9ec((int)psVar6);
        }
        *(float *)(psVar6 + 4) = (float)dVar20;
        *(byte *)(psVar6 + 0x1b) = bVar2;
        *psVar6 = sVar4;
        *(float *)(psVar6 + 8) = (float)dVar18;
      }
    }
  }
  FUN_80286870();
  return;
}

