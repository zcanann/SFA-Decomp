// Function: FUN_802a6df4
// Entry: 802a6df4
// Size: 2764 bytes

/* WARNING: Removing unreachable block (ram,0x802a78a0) */
/* WARNING: Removing unreachable block (ram,0x802a7898) */
/* WARNING: Removing unreachable block (ram,0x802a6e0c) */
/* WARNING: Removing unreachable block (ram,0x802a6e04) */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_802a6df4(void)

{
  byte bVar1;
  float fVar2;
  float fVar3;
  bool bVar4;
  short *psVar5;
  uint uVar6;
  int iVar7;
  short sVar8;
  uint *puVar9;
  int iVar10;
  int iVar11;
  float *in_r6;
  undefined4 *in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  int in_r10;
  int iVar12;
  double dVar13;
  undefined8 extraout_f1;
  double dVar14;
  double dVar15;
  double dVar16;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  double dVar17;
  undefined8 uVar18;
  undefined8 local_60;
  
  uVar18 = FUN_80286840();
  fVar2 = FLOAT_803e8b3c;
  psVar5 = (short *)((ulonglong)uVar18 >> 0x20);
  puVar9 = (uint *)uVar18;
  iVar12 = *(int *)(psVar5 + 0x5c);
  uVar18 = extraout_f1;
  if (*(char *)((int)puVar9 + 0x27a) != '\0') {
    if ((*(short *)((int)puVar9 + 0x276) == 0x24) || (*(short *)((int)puVar9 + 0x276) == 0x25)) {
      if ((*(byte *)(iVar12 + 0x3f1) >> 5 & 1) == 0) {
        *(undefined4 *)(iVar12 + 0x494) = *(undefined4 *)(iVar12 + 0x474);
        *(short *)(iVar12 + 0x484) = (short)*(undefined4 *)(iVar12 + 0x474);
        *(undefined4 *)(iVar12 + 0x48c) = 0;
        *(undefined4 *)(iVar12 + 0x488) = 0;
      }
      else {
        *(float *)(iVar12 + 0x4c8) = FLOAT_803e8b3c;
        *(float *)(iVar12 + 0x4cc) = fVar2;
      }
    }
    else {
      puVar9[0xa5] = (uint)FLOAT_803e8b3c;
    }
    *(float *)(iVar12 + 0x814) = FLOAT_803e8b3c;
    uVar6 = FUN_80022264(800,0x44c);
    *(short *)(iVar12 + 0x812) = (short)uVar6;
  }
  dVar15 = (double)*(float *)(iVar12 + 0x82c);
  dVar16 = (double)FLOAT_803dc074;
  dVar14 = FUN_80021434((double)(float)puVar9[0xa0],dVar15,dVar16);
  puVar9[0xa0] = (uint)(float)((double)(float)puVar9[0xa0] - dVar14);
  if ((float)puVar9[0xa0] <= DAT_80333eb8) {
    puVar9[0xa0] = (uint)FLOAT_803e8b3c;
  }
  fVar2 = FLOAT_803e8b3c;
  puVar9[0xa1] = (uint)FLOAT_803e8b3c;
  *(float *)(psVar5 + 0x12) = fVar2;
  *(float *)(psVar5 + 0x16) = fVar2;
  iVar7 = FUN_802acf3c(uVar18,dVar15,dVar16,in_f4,in_f5,in_f6,in_f7,in_f8,psVar5,(int)puVar9,iVar12,
                       in_r6,in_r7,in_r8,in_r9,in_r10);
  if (iVar7 == 0) {
    if ((((float)puVar9[0xa7] < FLOAT_803e8c60) || ((float)puVar9[0xa6] < FLOAT_803e8c60)) ||
       ((float)puVar9[0xa5] < *(float *)(*(int *)(iVar12 + 0x400) + 4))) {
      FUN_802ad964(psVar5,iVar12);
      if (*(short **)(iVar12 + 0x3f8) == (short *)&DAT_80333cb0) {
        if ((*(float *)(iVar12 + 0x814) < FLOAT_803e8c54) || ('\x04' < **(char **)(iVar12 + 0x35c)))
        {
          iVar7 = (int)_DAT_80333cb0;
          dVar14 = (double)FLOAT_803e8c10;
          if (*(short *)(iVar12 + 0x812) < 1) {
            if (*(char *)(iVar12 + 0x8c8) != 'D') {
              uVar6 = (uint)*(byte *)(iVar12 + 0x86f);
              iVar7 = (int)(&DAT_803dd334)[uVar6];
              if (*(short *)(iVar12 + 0x81a) == 0) {
                fVar2 = *(float *)(&DAT_80333c90 + uVar6 * 4);
              }
              else {
                fVar2 = *(float *)(&DAT_80333ca0 + uVar6 * 4);
              }
              dVar14 = (double)fVar2;
              *(char *)(iVar12 + 0x86f) = *(char *)(iVar12 + 0x86f) + '\x01';
              *(byte *)(iVar12 + 0x86f) = *(byte *)(iVar12 + 0x86f) % 3;
            }
            uVar6 = FUN_80022264(800,0x44c);
            *(short *)(iVar12 + 0x812) = (short)uVar6;
          }
        }
        else {
          iVar7 = 0x5d;
          dVar14 = (double)FLOAT_803e8c10;
          dVar15 = (double)FLOAT_803e8ba8;
          uVar6 = FUN_80022150((double)FLOAT_803e8b6c,dVar15,(float *)(iVar12 + 0x3ec));
          if (uVar6 != 0) {
            FUN_8000bb38((uint)psVar5,0x452);
          }
        }
        if (psVar5[0x50] == **(short **)(iVar12 + 0x3f8)) {
          *(float *)(iVar12 + 0x814) = *(float *)(iVar12 + 0x814) + FLOAT_803dc074;
          fVar2 = *(float *)(iVar12 + 0x814);
          fVar3 = FLOAT_803e8b3c;
          if ((FLOAT_803e8b3c <= fVar2) && (fVar3 = fVar2, FLOAT_803e8c54 < fVar2)) {
            fVar3 = FLOAT_803e8c54;
          }
          *(float *)(iVar12 + 0x814) = fVar3;
          *(short *)(iVar12 + 0x812) =
               (short)(int)((float)((double)CONCAT44(0x43300000,
                                                     (int)*(short *)(iVar12 + 0x812) ^ 0x80000000) -
                                   DOUBLE_803e8b58) - FLOAT_803dc074);
          sVar8 = *(short *)(iVar12 + 0x812);
          if (sVar8 < 0) {
            sVar8 = 0;
          }
          else if (0x44c < sVar8) {
            sVar8 = 0x44c;
          }
          *(short *)(iVar12 + 0x812) = sVar8;
        }
        else {
          if (psVar5[0x50] != 0x5d) {
            *(float *)(iVar12 + 0x814) = FLOAT_803e8b3c;
          }
          uVar6 = FUN_80022264(800,0x44c);
          *(short *)(iVar12 + 0x812) = (short)uVar6;
        }
      }
      else {
        iVar7 = (int)**(short **)(iVar12 + 0x3f8);
        dVar14 = (double)FLOAT_803e8c10;
      }
      if ((*(byte *)(iVar12 + 0x3f0) >> 5 & 1) == 0) {
        if ((*(byte *)(iVar12 + 0x3f1) >> 5 & 1) == 0) {
          *(uint *)(iVar12 + 0x360) = *(uint *)(iVar12 + 0x360) | 0x2000000;
          *(undefined2 *)(puVar9 + 0x9e) = 0;
          *(float *)(iVar12 + 0x404) = FLOAT_803e8d04;
        }
        else {
          *(uint *)(iVar12 + 0x360) = *(uint *)(iVar12 + 0x360) | 0x2000000;
          *(undefined2 *)(puVar9 + 0x9e) = 0;
          *(float *)(iVar12 + 0x404) = FLOAT_803e8b6c;
        }
      }
      else {
        *puVar9 = *puVar9 | 0x200000;
        *(uint *)(iVar12 + 0x360) = *(uint *)(iVar12 + 0x360) & 0xfdffffff;
        *(undefined2 *)(puVar9 + 0x9e) = 1;
        *(code **)(iVar12 + 0x898) = FUN_802a58ac;
        if ((*(byte *)(iVar12 + 0x3f1) >> 5 & 1) == 0) {
          *(float *)(iVar12 + 0x404) = FLOAT_803e8cfc;
        }
        else {
          *(float *)(iVar12 + 0x404) = FLOAT_803e8bc4;
        }
      }
      dVar13 = (double)(((float)puVar9[0xa6] - FLOAT_803e8bac) / FLOAT_803e8bc4);
      dVar17 = (double)FLOAT_803e8b3c;
      if ((dVar17 <= dVar13) && (dVar17 = dVar13, (double)FLOAT_803e8b78 < dVar13)) {
        dVar17 = (double)FLOAT_803e8b78;
      }
      dVar13 = (double)(*(float *)(iVar12 + 0x404) - FLOAT_803e8c04);
      *(float *)(iVar12 + 0x408) =
           (float)(dVar13 * (double)(float)(dVar17 * (double)*(float *)(iVar12 + 0x840)));
      if ((*(byte *)(iVar12 + 0x3f0) >> 5 & 1) != 0) {
        dVar13 = (double)FUN_802ae5e0(psVar5,iVar12,(int)puVar9);
      }
      bVar1 = *(byte *)(iVar12 + 0x3f0);
      if (((((((bVar1 >> 5 & 1) == 0) && ((bVar1 >> 6 & 1) == 0)) && ((bVar1 >> 4 & 1) == 0)) &&
           (((bVar1 >> 2 & 1) == 0 && ((bVar1 >> 3 & 1) == 0)))) && ((bVar1 >> 1 & 1) == 0)) &&
         ((*(int *)(iVar12 + 0x7f8) == 0 && (*(char *)(iVar12 + 0x8c8) != 'D')))) {
        bVar4 = true;
      }
      else {
        bVar4 = false;
      }
      if ((bVar4) && ((*(ushort *)(iVar12 + 0x6e2) & 0x400) != 0)) {
        FUN_802af48c(dVar13,dVar15,dVar16,in_f4,in_f5,in_f6,in_f7,in_f8,psVar5,iVar12,(int)puVar9,
                     in_r6,in_r7,in_r8,in_r9,in_r10);
        puVar9[0xc2] = (uint)FUN_802a58ac;
      }
      else {
        if ((*(byte *)(iVar12 + 0x3f1) >> 5 & 1) == 0) {
          dVar15 = (double)*(float *)(iVar12 + 0x438);
          dVar16 = (double)FLOAT_803dc074;
          dVar13 = FUN_80021434((double)(*(float *)(iVar12 + 0x408) - (float)puVar9[0xa5]),dVar15,
                                dVar16);
          puVar9[0xa5] = (uint)(float)((double)(float)puVar9[0xa5] + dVar13);
        }
        if (*(char *)((int)puVar9 + 0x27a) != '\0') {
          *(undefined4 *)(iVar12 + 0x47c) = 0;
          *(undefined4 *)(iVar12 + 0x480) = 0;
          *(undefined4 *)(iVar12 + 0x488) = 0;
          *(undefined4 *)(iVar12 + 0x48c) = 0;
          *(undefined *)(iVar12 + 0x8a6) = *(undefined *)(iVar12 + 0x8a3);
          *(undefined *)(iVar12 + 0x8b0) = 0;
          puVar9[0xae] = (uint)FLOAT_803e8cb0;
          puVar9[0xa8] = (uint)FLOAT_803e8d1c;
          if (((*(byte *)(iVar12 + 0x3f0) >> 5 & 1) == 0) &&
             ((*(byte *)(iVar12 + 0x3f1) >> 5 & 1) == 0)) {
            if (*(short *)((int)puVar9 + 0x276) == 2) {
              iVar10 = (int)*(short *)(*(int *)(iVar12 + 0x3f8) + 0x30);
              if (((psVar5[0x50] != iVar10) &&
                  (iVar11 = (int)*(short *)(*(int *)(iVar12 + 0x3f8) + 0x32), psVar5[0x50] != iVar11
                  )) && ((*(byte *)(iVar12 + 0x3f3) >> 6 & 1) == 0)) {
                if (FLOAT_803e8b30 < *(float *)(psVar5 + 0x4c)) {
                  FUN_8003042c((double)FLOAT_803e8b3c,dVar15,dVar16,in_f4,in_f5,in_f6,in_f7,in_f8,
                               psVar5,iVar11,0,in_r6,in_r7,in_r8,in_r9,in_r10);
                }
                else {
                  FUN_8003042c((double)FLOAT_803e8b3c,dVar15,dVar16,in_f4,in_f5,in_f6,in_f7,in_f8,
                               psVar5,iVar10,0,in_r6,in_r7,in_r8,in_r9,in_r10);
                }
              }
              puVar9[0xa8] = (uint)FLOAT_803e8d20;
            }
            else if (psVar5[0x50] != iVar7) {
              FUN_8003042c((double)FLOAT_803e8b3c,dVar15,dVar16,in_f4,in_f5,in_f6,in_f7,in_f8,psVar5
                           ,iVar7,0,in_r6,in_r7,in_r8,in_r9,in_r10);
              puVar9[0xa8] = (uint)(float)dVar14;
            }
          }
          else if (psVar5[0x50] != iVar7) {
            FUN_8003042c((double)FLOAT_803e8b3c,dVar15,dVar16,in_f4,in_f5,in_f6,in_f7,in_f8,psVar5,
                         iVar7,0,in_r6,in_r7,in_r8,in_r9,in_r10);
            puVar9[0xa8] = (uint)(float)dVar14;
          }
        }
        iVar11 = (int)psVar5[0x50];
        iVar10 = *(int *)(iVar12 + 0x3f8);
        if ((iVar11 == *(short *)(iVar10 + 0x30)) || (iVar11 == *(short *)(iVar10 + 0x32))) {
          if ((*(char *)((int)puVar9 + 0x346) != '\0') &&
             (sVar8 = FUN_8002f604((int)psVar5), sVar8 == 0)) {
            FUN_8003042c((double)FLOAT_803e8b3c,dVar15,dVar16,in_f4,in_f5,in_f6,in_f7,in_f8,psVar5,
                         iVar7,0,in_r6,in_r7,in_r8,in_r9,in_r10);
            puVar9[0xa8] = (uint)(float)dVar14;
          }
        }
        else if ((((*(byte *)(iVar12 + 0x3f0) >> 5 & 1) == 0) &&
                 ((*(byte *)(iVar12 + 0x3f1) >> 5 & 1) == 0)) && (5 < *(int *)(iVar12 + 0x47c))) {
          if ((iVar11 != *(short *)(iVar10 + 0x3e)) &&
             (sVar8 = FUN_8002f604((int)psVar5), sVar8 == 0)) {
            FUN_8003042c((double)FLOAT_803e8b3c,dVar15,dVar16,in_f4,in_f5,in_f6,in_f7,in_f8,psVar5,
                         (int)*(short *)(*(int *)(iVar12 + 0x3f8) + 0x3e),0,in_r6,in_r7,in_r8,in_r9,
                         in_r10);
            puVar9[0xa8] = (uint)FLOAT_803e8b28;
          }
        }
        else if ((iVar11 != iVar7) && (sVar8 = FUN_8002f604((int)psVar5), sVar8 == 0)) {
          sVar8 = psVar5[0x50];
          if ((sVar8 == DAT_803dd334) ||
             (((sVar8 == sRam803dd336 || (sVar8 == sRam803dd338)) || (sVar8 == sRam803dd33a)))) {
            if (*(char *)((int)puVar9 + 0x346) != '\0') {
              FUN_8003042c((double)FLOAT_803e8b3c,dVar15,dVar16,in_f4,in_f5,in_f6,in_f7,in_f8,psVar5
                           ,iVar7,0,in_r6,in_r7,in_r8,in_r9,in_r10);
              puVar9[0xa8] = (uint)(float)dVar14;
            }
          }
          else {
            FUN_8003042c((double)FLOAT_803e8b3c,dVar15,dVar16,in_f4,in_f5,in_f6,in_f7,in_f8,psVar5,
                         iVar7,0,in_r6,in_r7,in_r8,in_r9,in_r10);
            puVar9[0xa8] = (uint)(float)dVar14;
            if (iVar7 == 0x5d) {
              FUN_8002f66c((int)psVar5,0x1e);
            }
          }
        }
        if ((*(byte *)(iVar12 + 0x3f1) >> 5 & 1) == 0) {
          local_60 = (double)CONCAT44(0x43300000,*(uint *)(iVar12 + 0x47c) ^ 0x80000000);
          dVar16 = FUN_80021434((double)(float)(local_60 - DOUBLE_803e8b58),
                                (double)(FLOAT_803e8b78 / *(float *)(iVar12 + 0x428)),
                                (double)FLOAT_803dc074);
          dVar14 = DOUBLE_803e8b58;
          dVar15 = (double)(FLOAT_803dc074 * *(float *)(iVar12 + 0x42c) * *(float *)(iVar12 + 0x420)
                           );
          if (dVar16 < dVar15) {
            dVar15 = dVar16;
          }
          if (*(int *)(iVar12 + 0x480) < 0) {
            dVar15 = -dVar15;
          }
          *(short *)(iVar12 + 0x478) =
               (short)(int)((double)FLOAT_803e8b98 * dVar15 +
                           (double)(float)((double)CONCAT44(0x43300000,
                                                            (int)*(short *)(iVar12 + 0x478) ^
                                                            0x80000000) - DOUBLE_803e8b58));
          dVar15 = FUN_80021434((double)(float)((double)CONCAT44(0x43300000,
                                                                 *(uint *)(iVar12 + 0x488) ^
                                                                 0x80000000) - dVar14),
                                (double)(FLOAT_803e8b78 / *(float *)(iVar12 + 0x430)),
                                (double)FLOAT_803dc074);
          dVar14 = (double)(*(float *)(iVar12 + 0x434) * FLOAT_803dc074);
          if (dVar15 < dVar14) {
            dVar14 = dVar15;
          }
          if (*(int *)(iVar12 + 0x48c) < 0) {
            dVar14 = -dVar14;
          }
          *(short *)(iVar12 + 0x484) =
               (short)(int)((double)FLOAT_803e8b98 * dVar14 +
                           (double)(float)((double)CONCAT44(0x43300000,
                                                            (int)*(short *)(iVar12 + 0x484) ^
                                                            0x80000000) - DOUBLE_803e8b58));
        }
        else {
          dVar14 = (double)FUN_802945e0();
          dVar15 = (double)(*(float *)(iVar12 + 0x404) * (float)(dVar17 * -dVar14));
          dVar14 = (double)FUN_80294964();
          dVar16 = (double)(*(float *)(iVar12 + 0x404) * (float)(dVar17 * -dVar14));
          dVar14 = FUN_80021434((double)(float)(dVar15 - (double)*(float *)(iVar12 + 0x4c8)),
                                (double)*(float *)(iVar12 + 0x438),(double)FLOAT_803dc074);
          dVar15 = FUN_80021434((double)(float)(dVar16 - (double)*(float *)(iVar12 + 0x4cc)),
                                (double)*(float *)(iVar12 + 0x438),(double)FLOAT_803dc074);
          *(float *)(iVar12 + 0x4c8) = (float)((double)*(float *)(iVar12 + 0x4c8) + dVar14);
          *(float *)(iVar12 + 0x4cc) = (float)((double)*(float *)(iVar12 + 0x4cc) + dVar15);
          dVar14 = FUN_80293900((double)(*(float *)(iVar12 + 0x4c8) * *(float *)(iVar12 + 0x4c8) +
                                        *(float *)(iVar12 + 0x4cc) * *(float *)(iVar12 + 0x4cc)));
          puVar9[0xa5] = (uint)(float)dVar14;
          fVar2 = (float)puVar9[0xa5];
          fVar3 = FLOAT_803e8b3c;
          if ((FLOAT_803e8b3c <= fVar2) && (fVar3 = fVar2, *(float *)(iVar12 + 0x404) < fVar2)) {
            fVar3 = *(float *)(iVar12 + 0x404);
          }
          puVar9[0xa5] = (uint)fVar3;
        }
        if ((*(byte *)(iVar12 + 0x3f0) >> 5 & 1) == 0) {
          FUN_802aca8c(psVar5,(int)puVar9,iVar12);
        }
      }
    }
    else {
      puVar9[0xc2] = (uint)FUN_802a58ac;
    }
  }
  FUN_8028688c();
  return;
}

