// Function: FUN_801e9c00
// Entry: 801e9c00
// Size: 1600 bytes

/* WARNING: Removing unreachable block (ram,0x801ea218) */
/* WARNING: Removing unreachable block (ram,0x801ea208) */
/* WARNING: Removing unreachable block (ram,0x801ea210) */
/* WARNING: Removing unreachable block (ram,0x801ea220) */

void FUN_801e9c00(void)

{
  undefined4 *puVar1;
  float *pfVar2;
  bool bVar3;
  float fVar4;
  undefined4 uVar5;
  short sVar6;
  undefined2 *puVar7;
  int iVar8;
  int iVar9;
  undefined4 *puVar10;
  int iVar11;
  float **ppfVar12;
  undefined4 *puVar13;
  int *piVar14;
  int iVar15;
  int iVar16;
  int iVar17;
  int iVar18;
  int iVar19;
  uint uVar20;
  undefined4 uVar21;
  double dVar22;
  undefined8 in_f28;
  double dVar23;
  undefined8 in_f29;
  double dVar24;
  undefined8 in_f30;
  double dVar25;
  undefined8 in_f31;
  double dVar26;
  undefined8 uVar27;
  float **local_148;
  undefined4 local_144;
  undefined4 local_140;
  undefined4 local_13c;
  undefined4 local_138;
  undefined4 local_134;
  undefined4 local_130;
  undefined2 local_12c;
  undefined2 local_12a;
  short local_128;
  float local_124;
  undefined4 local_120;
  undefined4 local_11c;
  undefined4 local_118;
  undefined auStack276 [60];
  undefined4 uStack216;
  float local_d4 [19];
  undefined4 local_88;
  uint uStack132;
  longlong local_80;
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar21 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  uVar27 = FUN_802860b8();
  puVar7 = (undefined2 *)((ulonglong)uVar27 >> 0x20);
  iVar9 = (int)uVar27;
  puVar13 = &uStack216;
  puVar10 = &DAT_802c2424;
  iVar19 = 9;
  do {
    puVar1 = puVar10 + 1;
    puVar10 = puVar10 + 2;
    uVar5 = *puVar10;
    puVar13[1] = *puVar1;
    puVar13 = puVar13 + 2;
    *puVar13 = uVar5;
    iVar19 = iVar19 + -1;
  } while (iVar19 != 0);
  iVar11 = 0;
  iVar19 = iVar9;
  do {
    dVar23 = DOUBLE_803e5b00;
    fVar4 = FLOAT_803e5af0;
    piVar14 = (int *)(iVar19 + 0x4c8);
    if ((*(byte *)(iVar19 + 0x4ce) & 1) != 0) {
      iVar17 = (int)*(short *)(iVar19 + 0x4cc) - 2;
      iVar18 = *piVar14;
      iVar16 = iVar18 + iVar17 * 0x10;
      uVar20 = (uint)(int)*(short *)(iVar19 + 0x4cc) >> 1;
      if (-1 < iVar17) {
        do {
          uStack132 = (int)*(short *)(iVar16 + 0xc) ^ 0x80000000;
          local_88 = 0x43300000;
          iVar17 = (int)-(fVar4 * FLOAT_803db414 -
                         (float)((double)CONCAT44(0x43300000,uStack132) - dVar23));
          local_80 = (longlong)iVar17;
          *(short *)(iVar16 + 0xc) = (short)iVar17;
          *(undefined2 *)(iVar16 + 0x1c) = *(undefined2 *)(iVar16 + 0xc);
          sVar6 = *(short *)(iVar16 + 0xc);
          if (sVar6 < 0) {
            sVar6 = 0;
          }
          else if (0xff < sVar6) {
            sVar6 = 0xff;
          }
          *(short *)(iVar16 + 0xc) = sVar6;
          sVar6 = *(short *)(iVar16 + 0x1c);
          if (sVar6 < 0) {
            sVar6 = 0;
          }
          else if (0xff < sVar6) {
            sVar6 = 0xff;
          }
          *(short *)(iVar16 + 0x1c) = sVar6;
          iVar16 = iVar16 + -0x20;
          uVar20 = uVar20 - 1;
        } while (uVar20 != 0);
      }
      iVar16 = (int)*(short *)(iVar19 + 0x4cc) - 2;
      iVar18 = iVar18 + iVar16 * 0x10;
      uVar20 = (uint)(int)*(short *)(iVar19 + 0x4cc) >> 1;
      if (-1 < iVar16) {
        do {
          if (iVar16 < 2) {
            if ((*(short *)(iVar18 + 0xc) < 1) && (*(short *)(iVar18 + 0x1c) < 1)) {
              *(short *)(iVar19 + 0x4cc) = *(short *)(iVar19 + 0x4cc) + -2;
            }
          }
          else if ((((*(short *)(iVar18 + 0xc) < 1) && (*(short *)(iVar18 + 0x1c) < 1)) &&
                   (*(short *)(iVar18 + -4) < 1)) && (*(short *)(iVar18 + -0x14) < 1)) {
            *(short *)(iVar19 + 0x4cc) = *(short *)(iVar19 + 0x4cc) + -2;
          }
          iVar18 = iVar18 + -0x20;
          iVar16 = iVar16 + -2;
          uVar20 = uVar20 - 1;
        } while (uVar20 != 0);
      }
      if (((piVar14 != *(int **)(iVar9 + 0x510)) && (piVar14 != *(int **)(iVar9 + 0x514))) &&
         ((piVar14 != *(int **)(iVar9 + 0x518) && (*(short *)(iVar19 + 0x4cc) == 0)))) {
        *(byte *)(iVar19 + 0x4ce) = *(byte *)(iVar19 + 0x4ce) & 0xfe;
      }
    }
    iVar19 = iVar19 + 8;
    iVar11 = iVar11 + 1;
  } while (iVar11 < 9);
  iVar18 = 0;
  iVar16 = 0;
  iVar11 = 0xc;
  dVar25 = (double)FLOAT_803e5ae8;
  dVar26 = (double)FLOAT_803e5af4;
  dVar23 = (double)FLOAT_803e5afc;
  dVar24 = (double)FLOAT_803e5aec;
  iVar19 = iVar9;
  do {
    local_120 = *(undefined4 *)(puVar7 + 0xc);
    local_11c = *(undefined4 *)(puVar7 + 0xe);
    local_118 = *(undefined4 *)(puVar7 + 0x10);
    local_12c = *puVar7;
    local_12a = puVar7[1];
    local_128 = puVar7[2] + (short)*(undefined4 *)(iVar9 + 0x410);
    local_124 = (float)dVar24;
    FUN_80021ee8(auStack276,&local_12c);
    FUN_800226cc((double)*(float *)((int)local_d4 + iVar16),
                 (double)*(float *)((int)local_d4 + iVar16 + 4),
                 (double)*(float *)((int)local_d4 + iVar16 + 8),auStack276,&local_144,&local_140,
                 &local_13c);
    FUN_800226cc((double)*(float *)((int)local_d4 + iVar11),
                 (double)*(float *)((int)local_d4 + iVar11 + 4),
                 (double)*(float *)((int)local_d4 + iVar11 + 8),auStack276,&local_138,&local_134,
                 &local_130);
    bVar3 = false;
    iVar17 = 0;
    pfVar2 = (float *)&stack0xfffffeb0;
    do {
      iVar8 = FUN_80065e50((double)pfVar2[3],(double)pfVar2[4],(double)pfVar2[5],puVar7,&local_148,0
                           ,0x20);
      iVar15 = 0;
      ppfVar12 = local_148;
      if (0 < iVar8) {
        do {
          dVar22 = (double)(**ppfVar12 - pfVar2[4]);
          if (iVar18 < 1) {
            if ((dVar23 <= dVar22) && (dVar22 < dVar26)) {
              bVar3 = true;
              pfVar2[4] = FLOAT_803e5af8 + *local_148[iVar15];
              break;
            }
          }
          else if ((dVar25 < dVar22) && (dVar22 < dVar26)) {
            bVar3 = true;
            pfVar2[4] = FLOAT_803e5af8 + *local_148[iVar15];
            break;
          }
          ppfVar12 = ppfVar12 + 1;
          iVar15 = iVar15 + 1;
          iVar8 = iVar8 + -1;
        } while (iVar8 != 0);
      }
      iVar17 = iVar17 + 1;
      pfVar2 = pfVar2 + 3;
    } while (iVar17 < 2);
    if ((*(char *)(iVar9 + 0x428) < '\0') || (!bVar3)) {
      *(undefined4 *)(iVar19 + 0x510) = 0;
    }
    else {
      piVar14 = *(int **)(iVar19 + 0x510);
      if (piVar14 == (int *)0x0) {
        uVar20 = 0;
        piVar14 = (int *)(iVar9 + 0x4c8);
        if ((*(byte *)(iVar9 + 0x4ce) & 1) != 0) {
          uVar20 = 1;
          piVar14 = (int *)(iVar9 + 0x4d0);
          if ((*(byte *)(iVar9 + 0x4d6) & 1) != 0) {
            uVar20 = 2;
            piVar14 = (int *)(iVar9 + 0x4d8);
            if ((*(byte *)(iVar9 + 0x4de) & 1) != 0) {
              uVar20 = 3;
              piVar14 = (int *)(iVar9 + 0x4e0);
              if ((*(byte *)(iVar9 + 0x4e6) & 1) != 0) {
                uVar20 = 4;
                piVar14 = (int *)(iVar9 + 0x4e8);
                if ((*(byte *)(iVar9 + 0x4ee) & 1) != 0) {
                  uVar20 = 5;
                  piVar14 = (int *)(iVar9 + 0x4f0);
                  if ((*(byte *)(iVar9 + 0x4f6) & 1) != 0) {
                    uVar20 = 6;
                    piVar14 = (int *)(iVar9 + 0x4f8);
                    if ((*(byte *)(iVar9 + 0x4fe) & 1) != 0) {
                      uVar20 = 7;
                      piVar14 = (int *)(iVar9 + 0x500);
                      if ((*(byte *)(iVar9 + 0x506) & 1) != 0) {
                        uVar20 = 8;
                        piVar14 = (int *)(iVar9 + 0x508);
                        if ((*(byte *)(iVar9 + 0x50e) & 1) != 0) {
                          uVar20 = 9;
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
        if (8 < uVar20) break;
        *(byte *)((int)piVar14 + 6) = *(byte *)((int)piVar14 + 6) | 1;
        *(undefined2 *)(piVar14 + 1) = 0;
        *(int **)(iVar19 + 0x510) = piVar14;
      }
      else {
        iVar8 = *(short *)(piVar14 + 1) + -1;
        iVar17 = iVar8 * 0x10;
        for (; -1 < iVar8; iVar8 = iVar8 + -1) {
          FUN_80003494(*piVar14 + (iVar8 + 2) * 0x10,*piVar14 + iVar17,0x10);
          iVar17 = iVar17 + -0x10;
        }
      }
      *(undefined4 *)*piVar14 = local_144;
      *(undefined4 *)(*piVar14 + 4) = local_140;
      *(undefined4 *)(*piVar14 + 8) = local_13c;
      *(undefined4 *)(*piVar14 + 0x10) = local_138;
      *(undefined4 *)(*piVar14 + 0x14) = local_134;
      *(undefined4 *)(*piVar14 + 0x18) = local_130;
      *(undefined2 *)(*piVar14 + 0xc) = 0xff;
      *(undefined2 *)(*piVar14 + 0x1c) = 0xff;
      *(undefined *)(*piVar14 + 0xe) = *(undefined *)(iVar9 + 0x4b4);
      *(undefined *)(*piVar14 + 0x1e) = *(undefined *)(iVar9 + 0x4b4);
      *(short *)(piVar14 + 1) = *(short *)(piVar14 + 1) + 2;
      *(undefined4 *)(iVar9 + 0x51c) = *(undefined4 *)(puVar7 + 0xc);
      *(undefined4 *)(iVar9 + 0x520) = *(undefined4 *)(puVar7 + 0xe);
      *(undefined4 *)(iVar9 + 0x524) = *(undefined4 *)(puVar7 + 0x10);
    }
    iVar16 = iVar16 + 0x18;
    iVar11 = iVar11 + 0x18;
    iVar19 = iVar19 + 4;
    iVar18 = iVar18 + 1;
  } while (iVar18 < 3);
  __psq_l0(auStack8,uVar21);
  __psq_l1(auStack8,uVar21);
  __psq_l0(auStack24,uVar21);
  __psq_l1(auStack24,uVar21);
  __psq_l0(auStack40,uVar21);
  __psq_l1(auStack40,uVar21);
  __psq_l0(auStack56,uVar21);
  __psq_l1(auStack56,uVar21);
  FUN_80286104();
  return;
}

