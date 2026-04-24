// Function: FUN_801ea238
// Entry: 801ea238
// Size: 1600 bytes

/* WARNING: Removing unreachable block (ram,0x801ea858) */
/* WARNING: Removing unreachable block (ram,0x801ea850) */
/* WARNING: Removing unreachable block (ram,0x801ea848) */
/* WARNING: Removing unreachable block (ram,0x801ea840) */
/* WARNING: Removing unreachable block (ram,0x801ea260) */
/* WARNING: Removing unreachable block (ram,0x801ea258) */
/* WARNING: Removing unreachable block (ram,0x801ea250) */
/* WARNING: Removing unreachable block (ram,0x801ea248) */

void FUN_801ea238(void)

{
  undefined4 *puVar1;
  float *pfVar2;
  bool bVar3;
  float fVar4;
  undefined4 uVar5;
  short sVar6;
  ushort *puVar7;
  int iVar8;
  int iVar9;
  undefined4 *puVar10;
  int iVar11;
  undefined4 *puVar12;
  int *piVar13;
  int iVar14;
  int iVar15;
  int iVar16;
  int iVar17;
  int iVar18;
  uint uVar19;
  double dVar20;
  double in_f28;
  double dVar21;
  double in_f29;
  double dVar22;
  double in_f30;
  double dVar23;
  double in_f31;
  double dVar24;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar25;
  undefined4 *local_148;
  float local_144;
  float local_140;
  float local_13c;
  float local_138;
  float local_134;
  float local_130;
  ushort local_12c;
  ushort local_12a;
  short local_128;
  float local_124;
  undefined4 local_120;
  undefined4 local_11c;
  undefined4 local_118;
  float afStack_114 [15];
  undefined4 uStack_d8;
  float local_d4 [19];
  undefined4 local_88;
  uint uStack_84;
  longlong local_80;
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
  uVar25 = FUN_8028681c();
  puVar7 = (ushort *)((ulonglong)uVar25 >> 0x20);
  iVar9 = (int)uVar25;
  puVar12 = &uStack_d8;
  puVar10 = &DAT_802c2ba4;
  iVar18 = 9;
  do {
    puVar1 = puVar10 + 1;
    puVar10 = puVar10 + 2;
    uVar5 = *puVar10;
    puVar12[1] = *puVar1;
    puVar12 = puVar12 + 2;
    *puVar12 = uVar5;
    iVar18 = iVar18 + -1;
  } while (iVar18 != 0);
  iVar11 = 0;
  iVar18 = iVar9;
  do {
    dVar21 = DOUBLE_803e6798;
    fVar4 = FLOAT_803e6788;
    piVar13 = (int *)(iVar18 + 0x4c8);
    if ((*(byte *)(iVar18 + 0x4ce) & 1) != 0) {
      iVar16 = (int)*(short *)(iVar18 + 0x4cc) - 2;
      iVar17 = *piVar13;
      iVar15 = iVar17 + iVar16 * 0x10;
      uVar19 = (uint)(int)*(short *)(iVar18 + 0x4cc) >> 1;
      if (-1 < iVar16) {
        do {
          uStack_84 = (int)*(short *)(iVar15 + 0xc) ^ 0x80000000;
          local_88 = 0x43300000;
          iVar16 = (int)-(fVar4 * FLOAT_803dc074 -
                         (float)((double)CONCAT44(0x43300000,uStack_84) - dVar21));
          local_80 = (longlong)iVar16;
          *(short *)(iVar15 + 0xc) = (short)iVar16;
          *(undefined2 *)(iVar15 + 0x1c) = *(undefined2 *)(iVar15 + 0xc);
          sVar6 = *(short *)(iVar15 + 0xc);
          if (sVar6 < 0) {
            sVar6 = 0;
          }
          else if (0xff < sVar6) {
            sVar6 = 0xff;
          }
          *(short *)(iVar15 + 0xc) = sVar6;
          sVar6 = *(short *)(iVar15 + 0x1c);
          if (sVar6 < 0) {
            sVar6 = 0;
          }
          else if (0xff < sVar6) {
            sVar6 = 0xff;
          }
          *(short *)(iVar15 + 0x1c) = sVar6;
          iVar15 = iVar15 + -0x20;
          uVar19 = uVar19 - 1;
        } while (uVar19 != 0);
      }
      iVar15 = (int)*(short *)(iVar18 + 0x4cc) - 2;
      iVar17 = iVar17 + iVar15 * 0x10;
      uVar19 = (uint)(int)*(short *)(iVar18 + 0x4cc) >> 1;
      if (-1 < iVar15) {
        do {
          if (iVar15 < 2) {
            if ((*(short *)(iVar17 + 0xc) < 1) && (*(short *)(iVar17 + 0x1c) < 1)) {
              *(short *)(iVar18 + 0x4cc) = *(short *)(iVar18 + 0x4cc) + -2;
            }
          }
          else if ((((*(short *)(iVar17 + 0xc) < 1) && (*(short *)(iVar17 + 0x1c) < 1)) &&
                   (*(short *)(iVar17 + -4) < 1)) && (*(short *)(iVar17 + -0x14) < 1)) {
            *(short *)(iVar18 + 0x4cc) = *(short *)(iVar18 + 0x4cc) + -2;
          }
          iVar17 = iVar17 + -0x20;
          iVar15 = iVar15 + -2;
          uVar19 = uVar19 - 1;
        } while (uVar19 != 0);
      }
      if (((piVar13 != *(int **)(iVar9 + 0x510)) && (piVar13 != *(int **)(iVar9 + 0x514))) &&
         ((piVar13 != *(int **)(iVar9 + 0x518) && (*(short *)(iVar18 + 0x4cc) == 0)))) {
        *(byte *)(iVar18 + 0x4ce) = *(byte *)(iVar18 + 0x4ce) & 0xfe;
      }
    }
    iVar18 = iVar18 + 8;
    iVar11 = iVar11 + 1;
  } while (iVar11 < 9);
  iVar17 = 0;
  iVar15 = 0;
  iVar11 = 0xc;
  dVar23 = (double)FLOAT_803e6780;
  dVar24 = (double)FLOAT_803e678c;
  dVar21 = (double)FLOAT_803e6794;
  dVar22 = (double)FLOAT_803e6784;
  iVar18 = iVar9;
  do {
    local_120 = *(undefined4 *)(puVar7 + 0xc);
    local_11c = *(undefined4 *)(puVar7 + 0xe);
    local_118 = *(undefined4 *)(puVar7 + 0x10);
    local_12c = *puVar7;
    local_12a = puVar7[1];
    local_128 = puVar7[2] + (short)*(undefined4 *)(iVar9 + 0x410);
    local_124 = (float)dVar22;
    FUN_80021fac(afStack_114,&local_12c);
    FUN_80022790((double)*(float *)((int)local_d4 + iVar15),
                 (double)*(float *)((int)local_d4 + iVar15 + 4),
                 (double)*(float *)((int)local_d4 + iVar15 + 8),afStack_114,&local_144,&local_140,
                 &local_13c);
    FUN_80022790((double)*(float *)((int)local_d4 + iVar11),
                 (double)*(float *)((int)local_d4 + iVar11 + 4),
                 (double)*(float *)((int)local_d4 + iVar11 + 8),afStack_114,&local_138,&local_134,
                 &local_130);
    bVar3 = false;
    iVar16 = 0;
    pfVar2 = (float *)&stack0xfffffeb0;
    do {
      iVar8 = FUN_80065fcc((double)pfVar2[3],(double)pfVar2[4],(double)pfVar2[5],puVar7,&local_148,0
                           ,0x20);
      iVar14 = 0;
      puVar10 = local_148;
      if (0 < iVar8) {
        do {
          dVar20 = (double)(*(float *)*puVar10 - pfVar2[4]);
          if (iVar17 < 1) {
            if ((dVar21 <= dVar20) && (dVar20 < dVar24)) {
              bVar3 = true;
              pfVar2[4] = FLOAT_803e6790 + *(float *)local_148[iVar14];
              break;
            }
          }
          else if ((dVar23 < dVar20) && (dVar20 < dVar24)) {
            bVar3 = true;
            pfVar2[4] = FLOAT_803e6790 + *(float *)local_148[iVar14];
            break;
          }
          puVar10 = puVar10 + 1;
          iVar14 = iVar14 + 1;
          iVar8 = iVar8 + -1;
        } while (iVar8 != 0);
      }
      iVar16 = iVar16 + 1;
      pfVar2 = pfVar2 + 3;
    } while (iVar16 < 2);
    if ((*(char *)(iVar9 + 0x428) < '\0') || (!bVar3)) {
      *(undefined4 *)(iVar18 + 0x510) = 0;
    }
    else {
      piVar13 = *(int **)(iVar18 + 0x510);
      if (piVar13 == (int *)0x0) {
        uVar19 = 0;
        piVar13 = (int *)(iVar9 + 0x4c8);
        if ((*(byte *)(iVar9 + 0x4ce) & 1) != 0) {
          uVar19 = 1;
          piVar13 = (int *)(iVar9 + 0x4d0);
          if ((*(byte *)(iVar9 + 0x4d6) & 1) != 0) {
            uVar19 = 2;
            piVar13 = (int *)(iVar9 + 0x4d8);
            if ((*(byte *)(iVar9 + 0x4de) & 1) != 0) {
              uVar19 = 3;
              piVar13 = (int *)(iVar9 + 0x4e0);
              if ((*(byte *)(iVar9 + 0x4e6) & 1) != 0) {
                uVar19 = 4;
                piVar13 = (int *)(iVar9 + 0x4e8);
                if ((*(byte *)(iVar9 + 0x4ee) & 1) != 0) {
                  uVar19 = 5;
                  piVar13 = (int *)(iVar9 + 0x4f0);
                  if ((*(byte *)(iVar9 + 0x4f6) & 1) != 0) {
                    uVar19 = 6;
                    piVar13 = (int *)(iVar9 + 0x4f8);
                    if ((*(byte *)(iVar9 + 0x4fe) & 1) != 0) {
                      uVar19 = 7;
                      piVar13 = (int *)(iVar9 + 0x500);
                      if ((*(byte *)(iVar9 + 0x506) & 1) != 0) {
                        uVar19 = 8;
                        piVar13 = (int *)(iVar9 + 0x508);
                        if ((*(byte *)(iVar9 + 0x50e) & 1) != 0) {
                          uVar19 = 9;
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
        if (8 < uVar19) break;
        *(byte *)((int)piVar13 + 6) = *(byte *)((int)piVar13 + 6) | 1;
        *(undefined2 *)(piVar13 + 1) = 0;
        *(int **)(iVar18 + 0x510) = piVar13;
      }
      else {
        iVar8 = *(short *)(piVar13 + 1) + -1;
        iVar16 = iVar8 * 0x10;
        for (; -1 < iVar8; iVar8 = iVar8 + -1) {
          FUN_80003494(*piVar13 + (iVar8 + 2) * 0x10,*piVar13 + iVar16,0x10);
          iVar16 = iVar16 + -0x10;
        }
      }
      *(float *)*piVar13 = local_144;
      *(float *)(*piVar13 + 4) = local_140;
      *(float *)(*piVar13 + 8) = local_13c;
      *(float *)(*piVar13 + 0x10) = local_138;
      *(float *)(*piVar13 + 0x14) = local_134;
      *(float *)(*piVar13 + 0x18) = local_130;
      *(undefined2 *)(*piVar13 + 0xc) = 0xff;
      *(undefined2 *)(*piVar13 + 0x1c) = 0xff;
      *(undefined *)(*piVar13 + 0xe) = *(undefined *)(iVar9 + 0x4b4);
      *(undefined *)(*piVar13 + 0x1e) = *(undefined *)(iVar9 + 0x4b4);
      *(short *)(piVar13 + 1) = *(short *)(piVar13 + 1) + 2;
      *(undefined4 *)(iVar9 + 0x51c) = *(undefined4 *)(puVar7 + 0xc);
      *(undefined4 *)(iVar9 + 0x520) = *(undefined4 *)(puVar7 + 0xe);
      *(undefined4 *)(iVar9 + 0x524) = *(undefined4 *)(puVar7 + 0x10);
    }
    iVar15 = iVar15 + 0x18;
    iVar11 = iVar11 + 0x18;
    iVar18 = iVar18 + 4;
    iVar17 = iVar17 + 1;
  } while (iVar17 < 3);
  FUN_80286868();
  return;
}

