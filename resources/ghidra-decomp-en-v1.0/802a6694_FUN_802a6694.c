// Function: FUN_802a6694
// Entry: 802a6694
// Size: 2764 bytes

/* WARNING: Removing unreachable block (ram,0x802a7138) */
/* WARNING: Removing unreachable block (ram,0x802a7140) */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_802a6694(void)

{
  byte bVar1;
  float fVar2;
  float fVar3;
  bool bVar4;
  short sVar5;
  int iVar6;
  undefined2 uVar9;
  int iVar7;
  int iVar8;
  uint *puVar10;
  uint uVar11;
  int iVar12;
  int iVar13;
  undefined4 uVar14;
  double dVar15;
  undefined8 extraout_f1;
  double dVar16;
  undefined8 in_f30;
  undefined8 in_f31;
  double dVar17;
  undefined8 uVar18;
  double local_60;
  double local_40;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar14 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar18 = FUN_802860dc();
  fVar2 = FLOAT_803e7ea4;
  iVar6 = (int)((ulonglong)uVar18 >> 0x20);
  puVar10 = (uint *)uVar18;
  iVar13 = *(int *)(iVar6 + 0xb8);
  uVar18 = extraout_f1;
  if (*(char *)((int)puVar10 + 0x27a) != '\0') {
    if ((*(short *)((int)puVar10 + 0x276) == 0x24) || (*(short *)((int)puVar10 + 0x276) == 0x25)) {
      if ((*(byte *)(iVar13 + 0x3f1) >> 5 & 1) == 0) {
        *(undefined4 *)(iVar13 + 0x494) = *(undefined4 *)(iVar13 + 0x474);
        *(short *)(iVar13 + 0x484) = (short)*(undefined4 *)(iVar13 + 0x474);
        *(undefined4 *)(iVar13 + 0x48c) = 0;
        *(undefined4 *)(iVar13 + 0x488) = 0;
      }
      else {
        *(float *)(iVar13 + 0x4c8) = FLOAT_803e7ea4;
        *(float *)(iVar13 + 0x4cc) = fVar2;
      }
    }
    else {
      puVar10[0xa5] = (uint)FLOAT_803e7ea4;
    }
    *(float *)(iVar13 + 0x814) = FLOAT_803e7ea4;
    uVar9 = FUN_800221a0(800,0x44c);
    *(undefined2 *)(iVar13 + 0x812) = uVar9;
  }
  dVar16 = (double)FUN_80021370((double)(float)puVar10[0xa0],(double)*(float *)(iVar13 + 0x82c),
                                (double)FLOAT_803db414);
  puVar10[0xa0] = (uint)(float)((double)(float)puVar10[0xa0] - dVar16);
  if ((float)puVar10[0xa0] <= DAT_80333258) {
    puVar10[0xa0] = (uint)FLOAT_803e7ea4;
  }
  fVar2 = FLOAT_803e7ea4;
  puVar10[0xa1] = (uint)FLOAT_803e7ea4;
  *(float *)(iVar6 + 0x24) = fVar2;
  *(float *)(iVar6 + 0x2c) = fVar2;
  iVar7 = FUN_802ac7dc(uVar18,iVar6,puVar10,iVar13);
  if (iVar7 == 0) {
    if ((((float)puVar10[0xa7] < FLOAT_803e7fc8) || ((float)puVar10[0xa6] < FLOAT_803e7fc8)) ||
       ((float)puVar10[0xa5] < *(float *)(*(int *)(iVar13 + 0x400) + 4))) {
      FUN_802ad204(iVar6,iVar13);
      if (*(short **)(iVar13 + 0x3f8) == (short *)&DAT_80333050) {
        if ((*(float *)(iVar13 + 0x814) < FLOAT_803e7fbc) || ('\x04' < **(char **)(iVar13 + 0x35c)))
        {
          iVar7 = (int)_DAT_80333050;
          dVar16 = (double)FLOAT_803e7f78;
          if (*(short *)(iVar13 + 0x812) < 1) {
            if (*(char *)(iVar13 + 0x8c8) != 'D') {
              uVar11 = (uint)*(byte *)(iVar13 + 0x86f);
              iVar7 = (int)(&DAT_803dc6cc)[uVar11];
              if (*(short *)(iVar13 + 0x81a) == 0) {
                fVar2 = *(float *)(&DAT_80333030 + uVar11 * 4);
              }
              else {
                fVar2 = *(float *)(&DAT_80333040 + uVar11 * 4);
              }
              dVar16 = (double)fVar2;
              *(char *)(iVar13 + 0x86f) = *(char *)(iVar13 + 0x86f) + '\x01';
              *(byte *)(iVar13 + 0x86f) = *(byte *)(iVar13 + 0x86f) % 3;
            }
            uVar9 = FUN_800221a0(800,0x44c);
            *(undefined2 *)(iVar13 + 0x812) = uVar9;
          }
        }
        else {
          iVar7 = 0x5d;
          dVar16 = (double)FLOAT_803e7f78;
          iVar8 = FUN_8002208c((double)FLOAT_803e7ed4,(double)FLOAT_803e7f10,iVar13 + 0x3ec);
          if (iVar8 != 0) {
            FUN_8000bb18(iVar6,0x452);
          }
        }
        if (*(short *)(iVar6 + 0xa0) == **(short **)(iVar13 + 0x3f8)) {
          *(float *)(iVar13 + 0x814) = *(float *)(iVar13 + 0x814) + FLOAT_803db414;
          fVar2 = *(float *)(iVar13 + 0x814);
          fVar3 = FLOAT_803e7ea4;
          if ((FLOAT_803e7ea4 <= fVar2) && (fVar3 = fVar2, FLOAT_803e7fbc < fVar2)) {
            fVar3 = FLOAT_803e7fbc;
          }
          *(float *)(iVar13 + 0x814) = fVar3;
          *(short *)(iVar13 + 0x812) =
               (short)(int)((float)((double)CONCAT44(0x43300000,
                                                     (int)*(short *)(iVar13 + 0x812) ^ 0x80000000) -
                                   DOUBLE_803e7ec0) - FLOAT_803db414);
          sVar5 = *(short *)(iVar13 + 0x812);
          if (sVar5 < 0) {
            sVar5 = 0;
          }
          else if (0x44c < sVar5) {
            sVar5 = 0x44c;
          }
          *(short *)(iVar13 + 0x812) = sVar5;
        }
        else {
          if (*(short *)(iVar6 + 0xa0) != 0x5d) {
            *(float *)(iVar13 + 0x814) = FLOAT_803e7ea4;
          }
          uVar9 = FUN_800221a0(800,0x44c);
          *(undefined2 *)(iVar13 + 0x812) = uVar9;
        }
      }
      else {
        iVar7 = (int)**(short **)(iVar13 + 0x3f8);
        dVar16 = (double)FLOAT_803e7f78;
      }
      if ((*(byte *)(iVar13 + 0x3f0) >> 5 & 1) == 0) {
        if ((*(byte *)(iVar13 + 0x3f1) >> 5 & 1) == 0) {
          *(uint *)(iVar13 + 0x360) = *(uint *)(iVar13 + 0x360) | 0x2000000;
          *(undefined2 *)(puVar10 + 0x9e) = 0;
          *(float *)(iVar13 + 0x404) = FLOAT_803e806c;
        }
        else {
          *(uint *)(iVar13 + 0x360) = *(uint *)(iVar13 + 0x360) | 0x2000000;
          *(undefined2 *)(puVar10 + 0x9e) = 0;
          *(float *)(iVar13 + 0x404) = FLOAT_803e7ed4;
        }
      }
      else {
        *puVar10 = *puVar10 | 0x200000;
        *(uint *)(iVar13 + 0x360) = *(uint *)(iVar13 + 0x360) & 0xfdffffff;
        *(undefined2 *)(puVar10 + 0x9e) = 1;
        *(code **)(iVar13 + 0x898) = FUN_802a514c;
        if ((*(byte *)(iVar13 + 0x3f1) >> 5 & 1) == 0) {
          *(float *)(iVar13 + 0x404) = FLOAT_803e8064;
        }
        else {
          *(float *)(iVar13 + 0x404) = FLOAT_803e7f2c;
        }
      }
      dVar15 = (double)(((float)puVar10[0xa6] - FLOAT_803e7f14) / FLOAT_803e7f2c);
      dVar17 = (double)FLOAT_803e7ea4;
      if ((dVar17 <= dVar15) && (dVar17 = dVar15, (double)FLOAT_803e7ee0 < dVar15)) {
        dVar17 = (double)FLOAT_803e7ee0;
      }
      *(float *)(iVar13 + 0x408) =
           (*(float *)(iVar13 + 0x404) - FLOAT_803e7f6c) *
           (float)(dVar17 * (double)*(float *)(iVar13 + 0x840));
      if ((*(byte *)(iVar13 + 0x3f0) >> 5 & 1) != 0) {
        FUN_802ade80(iVar6,iVar13,puVar10);
      }
      bVar1 = *(byte *)(iVar13 + 0x3f0);
      if (((((((bVar1 >> 5 & 1) == 0) && ((bVar1 >> 6 & 1) == 0)) && ((bVar1 >> 4 & 1) == 0)) &&
           (((bVar1 >> 2 & 1) == 0 && ((bVar1 >> 3 & 1) == 0)))) && ((bVar1 >> 1 & 1) == 0)) &&
         ((*(int *)(iVar13 + 0x7f8) == 0 && (*(char *)(iVar13 + 0x8c8) != 'D')))) {
        bVar4 = true;
      }
      else {
        bVar4 = false;
      }
      if ((bVar4) && ((*(ushort *)(iVar13 + 0x6e2) & 0x400) != 0)) {
        FUN_802aed2c(iVar6,iVar13,puVar10);
        puVar10[0xc2] = (uint)FUN_802a514c;
        iVar7 = 3;
      }
      else {
        if ((*(byte *)(iVar13 + 0x3f1) >> 5 & 1) == 0) {
          dVar15 = (double)FUN_80021370((double)(*(float *)(iVar13 + 0x408) - (float)puVar10[0xa5]),
                                        (double)*(float *)(iVar13 + 0x438),(double)FLOAT_803db414);
          puVar10[0xa5] = (uint)(float)((double)(float)puVar10[0xa5] + dVar15);
        }
        if (*(char *)((int)puVar10 + 0x27a) != '\0') {
          *(undefined4 *)(iVar13 + 0x47c) = 0;
          *(undefined4 *)(iVar13 + 0x480) = 0;
          *(undefined4 *)(iVar13 + 0x488) = 0;
          *(undefined4 *)(iVar13 + 0x48c) = 0;
          *(undefined *)(iVar13 + 0x8a6) = *(undefined *)(iVar13 + 0x8a3);
          *(undefined *)(iVar13 + 0x8b0) = 0;
          puVar10[0xae] = (uint)FLOAT_803e8018;
          puVar10[0xa8] = (uint)FLOAT_803e8084;
          if (((*(byte *)(iVar13 + 0x3f0) >> 5 & 1) == 0) &&
             ((*(byte *)(iVar13 + 0x3f1) >> 5 & 1) == 0)) {
            if (*(short *)((int)puVar10 + 0x276) == 2) {
              iVar8 = (int)*(short *)(*(int *)(iVar13 + 0x3f8) + 0x30);
              if (((*(short *)(iVar6 + 0xa0) != iVar8) &&
                  (iVar12 = (int)*(short *)(*(int *)(iVar13 + 0x3f8) + 0x32),
                  *(short *)(iVar6 + 0xa0) != iVar12)) &&
                 ((*(byte *)(iVar13 + 0x3f3) >> 6 & 1) == 0)) {
                if (FLOAT_803e7e98 < *(float *)(iVar6 + 0x98)) {
                  FUN_80030334((double)FLOAT_803e7ea4,iVar6,iVar12,0);
                }
                else {
                  FUN_80030334((double)FLOAT_803e7ea4,iVar6,iVar8,0);
                }
              }
              puVar10[0xa8] = (uint)FLOAT_803e8088;
            }
            else if (*(short *)(iVar6 + 0xa0) != iVar7) {
              FUN_80030334((double)FLOAT_803e7ea4,iVar6,iVar7,0);
              puVar10[0xa8] = (uint)(float)dVar16;
            }
          }
          else if (*(short *)(iVar6 + 0xa0) != iVar7) {
            FUN_80030334((double)FLOAT_803e7ea4,iVar6,iVar7,0);
            puVar10[0xa8] = (uint)(float)dVar16;
          }
        }
        iVar12 = (int)*(short *)(iVar6 + 0xa0);
        iVar8 = *(int *)(iVar13 + 0x3f8);
        if ((iVar12 == *(short *)(iVar8 + 0x30)) || (iVar12 == *(short *)(iVar8 + 0x32))) {
          if ((*(char *)((int)puVar10 + 0x346) != '\0') && (iVar8 = FUN_8002f50c(iVar6), iVar8 == 0)
             ) {
            FUN_80030334((double)FLOAT_803e7ea4,iVar6,iVar7,0);
            puVar10[0xa8] = (uint)(float)dVar16;
          }
        }
        else if ((((*(byte *)(iVar13 + 0x3f0) >> 5 & 1) == 0) &&
                 ((*(byte *)(iVar13 + 0x3f1) >> 5 & 1) == 0)) && (5 < *(int *)(iVar13 + 0x47c))) {
          if ((iVar12 != *(short *)(iVar8 + 0x3e)) && (iVar7 = FUN_8002f50c(iVar6), iVar7 == 0)) {
            FUN_80030334((double)FLOAT_803e7ea4,iVar6,
                         (int)*(short *)(*(int *)(iVar13 + 0x3f8) + 0x3e),0);
            puVar10[0xa8] = (uint)FLOAT_803e7e90;
          }
        }
        else if ((iVar12 != iVar7) && (iVar8 = FUN_8002f50c(iVar6), iVar8 == 0)) {
          sVar5 = *(short *)(iVar6 + 0xa0);
          if ((sVar5 == DAT_803dc6cc) ||
             (((sVar5 == sRam803dc6ce || (sVar5 == sRam803dc6d0)) || (sVar5 == sRam803dc6d2)))) {
            if (*(char *)((int)puVar10 + 0x346) != '\0') {
              FUN_80030334((double)FLOAT_803e7ea4,iVar6,iVar7,0);
              puVar10[0xa8] = (uint)(float)dVar16;
            }
          }
          else {
            FUN_80030334((double)FLOAT_803e7ea4,iVar6,iVar7,0);
            puVar10[0xa8] = (uint)(float)dVar16;
            if (iVar7 == 0x5d) {
              FUN_8002f574(iVar6,0x1e);
            }
          }
        }
        if ((*(byte *)(iVar13 + 0x3f1) >> 5 & 1) == 0) {
          local_60 = (double)CONCAT44(0x43300000,*(uint *)(iVar13 + 0x47c) ^ 0x80000000);
          dVar15 = (double)FUN_80021370((double)(float)(local_60 - DOUBLE_803e7ec0),
                                        (double)(FLOAT_803e7ee0 / *(float *)(iVar13 + 0x428)),
                                        (double)FLOAT_803db414);
          dVar16 = DOUBLE_803e7ec0;
          dVar17 = (double)(FLOAT_803db414 * *(float *)(iVar13 + 0x42c) * *(float *)(iVar13 + 0x420)
                           );
          if (dVar15 < dVar17) {
            dVar17 = dVar15;
          }
          if (*(int *)(iVar13 + 0x480) < 0) {
            dVar17 = -dVar17;
          }
          *(short *)(iVar13 + 0x478) =
               (short)(int)((double)FLOAT_803e7f00 * dVar17 +
                           (double)(float)((double)CONCAT44(0x43300000,
                                                            (int)*(short *)(iVar13 + 0x478) ^
                                                            0x80000000) - DOUBLE_803e7ec0));
          dVar17 = (double)FUN_80021370((double)(float)((double)CONCAT44(0x43300000,
                                                                         *(uint *)(iVar13 + 0x488) ^
                                                                         0x80000000) - dVar16),
                                        (double)(FLOAT_803e7ee0 / *(float *)(iVar13 + 0x430)),
                                        (double)FLOAT_803db414);
          dVar16 = (double)(*(float *)(iVar13 + 0x434) * FLOAT_803db414);
          if (dVar17 < dVar16) {
            dVar16 = dVar17;
          }
          if (*(int *)(iVar13 + 0x48c) < 0) {
            dVar16 = -dVar16;
          }
          *(short *)(iVar13 + 0x484) =
               (short)(int)((double)FLOAT_803e7f00 * dVar16 +
                           (double)(float)((double)CONCAT44(0x43300000,
                                                            (int)*(short *)(iVar13 + 0x484) ^
                                                            0x80000000) - DOUBLE_803e7ec0));
        }
        else {
          local_40 = (double)CONCAT44(0x43300000,*(uint *)(iVar13 + 0x474) ^ 0x80000000);
          dVar16 = (double)FUN_80293e80((double)((FLOAT_803e7f94 *
                                                 (float)(local_40 - DOUBLE_803e7ec0)) /
                                                FLOAT_803e7f98));
          dVar15 = (double)(*(float *)(iVar13 + 0x404) * (float)(dVar17 * -dVar16));
          dVar16 = (double)FUN_80294204((double)((FLOAT_803e7f94 *
                                                 (float)((double)CONCAT44(0x43300000,
                                                                          *(uint *)(iVar13 + 0x474)
                                                                          ^ 0x80000000) -
                                                        DOUBLE_803e7ec0)) / FLOAT_803e7f98));
          dVar17 = (double)(*(float *)(iVar13 + 0x404) * (float)(dVar17 * -dVar16));
          dVar16 = (double)FUN_80021370((double)(float)(dVar15 - (double)*(float *)(iVar13 + 0x4c8))
                                        ,(double)*(float *)(iVar13 + 0x438),(double)FLOAT_803db414);
          dVar17 = (double)FUN_80021370((double)(float)(dVar17 - (double)*(float *)(iVar13 + 0x4cc))
                                        ,(double)*(float *)(iVar13 + 0x438),(double)FLOAT_803db414);
          *(float *)(iVar13 + 0x4c8) = (float)((double)*(float *)(iVar13 + 0x4c8) + dVar16);
          *(float *)(iVar13 + 0x4cc) = (float)((double)*(float *)(iVar13 + 0x4cc) + dVar17);
          dVar16 = (double)FUN_802931a0((double)(*(float *)(iVar13 + 0x4c8) *
                                                 *(float *)(iVar13 + 0x4c8) +
                                                *(float *)(iVar13 + 0x4cc) *
                                                *(float *)(iVar13 + 0x4cc)));
          puVar10[0xa5] = (uint)(float)dVar16;
          fVar2 = (float)puVar10[0xa5];
          fVar3 = FLOAT_803e7ea4;
          if ((FLOAT_803e7ea4 <= fVar2) && (fVar3 = fVar2, *(float *)(iVar13 + 0x404) < fVar2)) {
            fVar3 = *(float *)(iVar13 + 0x404);
          }
          puVar10[0xa5] = (uint)fVar3;
        }
        if ((*(byte *)(iVar13 + 0x3f0) >> 5 & 1) == 0) {
          FUN_802ac32c(iVar6,puVar10,iVar13);
        }
        iVar7 = 0;
      }
    }
    else {
      puVar10[0xc2] = (uint)FUN_802a514c;
      iVar7 = 3;
    }
  }
  __psq_l0(auStack8,uVar14);
  __psq_l1(auStack8,uVar14);
  __psq_l0(auStack24,uVar14);
  __psq_l1(auStack24,uVar14);
  FUN_80286128(iVar7);
  return;
}

