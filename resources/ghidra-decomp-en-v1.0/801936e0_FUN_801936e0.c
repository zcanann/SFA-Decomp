// Function: FUN_801936e0
// Entry: 801936e0
// Size: 1500 bytes

/* WARNING: Removing unreachable block (ram,0x80193c9c) */

void FUN_801936e0(void)

{
  byte bVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  char cVar10;
  undefined4 uVar5;
  short sVar9;
  int iVar6;
  ushort *puVar7;
  ushort *puVar8;
  bool bVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  int iVar15;
  int iVar16;
  int *piVar17;
  int iVar18;
  uint uVar19;
  int iVar20;
  int iVar21;
  int *piVar22;
  int iVar23;
  int iVar24;
  undefined4 uVar25;
  undefined8 in_f31;
  double dVar26;
  float local_78;
  undefined auStack116 [4];
  float local_70;
  undefined4 local_68;
  uint uStack100;
  undefined auStack8 [8];
  
  uVar25 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar4 = FUN_802860ac();
  FUN_8002b9ec();
  piVar17 = *(int **)(iVar4 + 0xb8);
  iVar16 = *(int *)(iVar4 + 0x4c);
  if (*(char *)(iVar16 + 0x25) != '\0') {
    cVar10 = FUN_8005b2fc((double)*(float *)(iVar4 + 0xc),(double)*(float *)(iVar4 + 0x10),
                          (double)*(float *)(iVar4 + 0x14));
    iVar12 = (int)cVar10;
    bVar1 = *(byte *)((int)piVar17 + 0x2d);
    if (iVar12 < 0) {
      *(byte *)((int)piVar17 + 0x2d) = bVar1 & 0xfe;
    }
    else {
      *(byte *)((int)piVar17 + 0x2d) = bVar1 | 1;
    }
    if ((*(byte *)((int)piVar17 + 0x2d) & 1) != (bVar1 & 1)) {
      *(undefined *)(piVar17 + 0xb) = 2;
    }
    bVar11 = (*(byte *)((int)piVar17 + 0x2d) & 1) != 0;
    if (bVar11) {
      if ((bVar11) && (*piVar17 == 0)) {
        uVar5 = FUN_8005aeec(iVar12);
        sVar9 = FUN_80060688(uVar5,*(undefined *)(iVar16 + 0x25));
        *(short *)(piVar17 + 10) = sVar9 * 3;
        if (0 < *(short *)(piVar17 + 10)) {
          iVar6 = FUN_80023cc8(*(short *)(piVar17 + 10) * 6,5,0);
          *piVar17 = iVar6;
          piVar17[1] = iVar6 + *(short *)(piVar17 + 10) * 4;
          FUN_801932c8(iVar4,piVar17,iVar16);
        }
      }
      if (*(short *)(piVar17 + 10) != 0) {
        if (*(char *)(iVar16 + 0x22) == '\0') {
          if (piVar17[2] == 0) {
            local_78 = FLOAT_803e3f98;
            iVar6 = FUN_80036e58(4,iVar4,&local_78);
            piVar17[2] = iVar6;
            iVar6 = piVar17[2];
            if (iVar6 != 0) {
              if (*(short *)(iVar6 + 0x46) == 0x519) {
                if ((*(byte *)((int)piVar17 + 0x2d) & 2) == 0) {
                  FUN_801a80f0(iVar6,1);
                }
                FUN_801a80c4((double)*(float *)(iVar4 + 0xc),
                             (double)(*(float *)(iVar4 + 0x10) - (float)piVar17[6]),
                             (double)*(float *)(iVar4 + 0x14),iVar6);
              }
              else {
                if ((*(byte *)((int)piVar17 + 0x2d) & 2) == 0) {
                  (**(code **)(**(int **)(iVar6 + 0x68) + 0x24))(iVar6,1);
                }
                (**(code **)(**(int **)(iVar6 + 0x68) + 0x38))
                          ((double)*(float *)(iVar4 + 0xc),
                           (double)(*(float *)(iVar4 + 0x10) - (float)piVar17[6]),
                           (double)*(float *)(iVar4 + 0x14),iVar6);
              }
            }
          }
          else if ((*(ushort *)(piVar17[2] + 0xb0) & 0x40) != 0) {
            piVar17[2] = 0;
          }
        }
        iVar12 = FUN_8005aeec(iVar12);
        fVar3 = FLOAT_803e3fb0;
        if ((iVar12 != 0) && ((*(ushort *)(iVar12 + 4) & 8) != 0)) {
          fVar2 = (float)piVar17[3];
          if (FLOAT_803e3fb0 < fVar2) {
            if ((*(byte *)((int)piVar17 + 0x2d) & 4) == 0) {
              uStack100 = (uint)*(byte *)(iVar16 + 0x20);
              local_68 = 0x43300000;
              if ((fVar2 < FLOAT_803e3f98 *
                           (float)((double)CONCAT44(0x43300000,uStack100) - DOUBLE_803e3fa0)) &&
                 (piVar17[3] = (int)(fVar2 - FLOAT_803db414), (float)piVar17[3] < fVar3)) {
                piVar17[3] = (int)fVar3;
              }
            }
            else {
              *(byte *)((int)piVar17 + 0x2d) = *(byte *)((int)piVar17 + 0x2d) & 0xfb;
            }
            if ((float)piVar17[3] != (float)piVar17[4]) {
              *(undefined *)(piVar17 + 0xb) = 2;
              piVar17[4] = piVar17[3];
            }
            if (*(char *)(piVar17 + 0xb) != '\0') {
              *(char *)(piVar17 + 0xb) = *(char *)(piVar17 + 0xb) + -1;
              uStack100 = (uint)*(byte *)(iVar16 + 0x20);
              local_68 = 0x43300000;
              fVar3 = FLOAT_803e3f98 *
                      (float)((double)CONCAT44(0x43300000,uStack100) - DOUBLE_803e3fa0);
              if (fVar3 < (float)piVar17[4]) {
                piVar17[4] = (int)fVar3;
                piVar17[3] = (int)fVar3;
                iVar6 = piVar17[2];
                if ((iVar6 != 0) && (*(int *)(iVar6 + 0xb8) != 0)) {
                  if (*(short *)(iVar6 + 0x46) == 0x519) {
                    FUN_801a80f0(iVar6,0);
                  }
                  else {
                    (**(code **)(**(int **)(iVar6 + 0x68) + 0x24))(iVar6,0);
                  }
                }
                FUN_800200e8((int)*(short *)(iVar16 + 0x18),1);
                *(byte *)((int)piVar17 + 0x2d) = *(byte *)((int)piVar17 + 0x2d) | 2;
                FUN_8000bb18(iVar4,*(undefined2 *)
                                    (&DAT_803dbdf0 + (uint)*(byte *)(iVar16 + 0x21) * 2));
              }
              iVar21 = 0;
              iVar20 = 0;
              dVar26 = (double)FLOAT_803e3fb0;
              piVar22 = piVar17;
              for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)((int)piVar17 + 0x2a); iVar6 = iVar6 + 1)
              {
                puVar7 = (ushort *)FUN_800606ec(iVar12,(int)*(short *)(piVar22 + 7));
                iVar13 = iVar20;
                iVar14 = iVar21;
                for (uVar19 = (uint)*puVar7; (int)uVar19 < (int)(uint)puVar7[10];
                    uVar19 = uVar19 + 1) {
                  puVar8 = (ushort *)FUN_800606dc(iVar12,uVar19);
                  iVar18 = 0;
                  iVar23 = iVar13;
                  iVar24 = iVar14;
                  do {
                    if (dVar26 < (double)*(float *)(*piVar17 + iVar14)) {
                      iVar15 = *(int *)(iVar12 + 0x58) + (uint)*puVar8 * 6;
                      FUN_800605f0(iVar15,auStack116);
                      uStack100 = (int)*(short *)(piVar17[1] + iVar13) ^ 0x80000000;
                      local_68 = 0x43300000;
                      local_70 = (float)((double)CONCAT44(0x43300000,uStack100) - DOUBLE_803e3fc8) -
                                 ((float)piVar17[4] / FLOAT_803e3f98) *
                                 *(float *)(*piVar17 + iVar14);
                      FUN_8006058c(iVar15,auStack116);
                    }
                    iVar14 = iVar14 + 4;
                    iVar13 = iVar13 + 2;
                    iVar24 = iVar24 + 4;
                    iVar23 = iVar23 + 2;
                    iVar21 = iVar21 + 4;
                    iVar20 = iVar20 + 2;
                    puVar8 = puVar8 + 1;
                    iVar18 = iVar18 + 1;
                  } while (iVar18 < 3);
                  iVar13 = iVar23;
                  iVar14 = iVar24;
                }
                piVar22 = (int *)((int)piVar22 + 2);
              }
              FUN_80241a80(*(undefined4 *)(iVar12 + 0x58),(uint)*(ushort *)(iVar12 + 0x90) * 6);
            }
          }
          if ((*(short *)(iVar16 + 0x1a) == -1) || (iVar16 = FUN_8001ffb4(), iVar16 != 0)) {
            bVar11 = true;
          }
          else {
            bVar11 = false;
          }
          if (((*(byte *)((int)piVar17 + 0x2d) & 2) == 0) && (bVar11)) {
            iVar16 = FUN_8002b9ac();
            if ((iVar16 == 0) || (iVar12 = FUN_8001ffb4(0x4e4), iVar12 == 0)) {
              *(byte *)(iVar4 + 0xaf) = *(byte *)(iVar4 + 0xaf) | 0x10;
            }
            else {
              *(byte *)(iVar4 + 0xaf) = *(byte *)(iVar4 + 0xaf) & 0xef;
            }
            *(byte *)(iVar4 + 0xaf) = *(byte *)(iVar4 + 0xaf) & 0xf7;
            if ((iVar16 != 0) && ((*(byte *)(iVar4 + 0xaf) & 4) != 0)) {
              (**(code **)(**(int **)(iVar16 + 0x68) + 0x28))(iVar16,iVar4,1,1);
            }
          }
          else {
            *(byte *)(iVar4 + 0xaf) = *(byte *)(iVar4 + 0xaf) | 8;
          }
          FUN_80041018(iVar4);
        }
      }
    }
  }
  __psq_l0(auStack8,uVar25);
  __psq_l1(auStack8,uVar25);
  FUN_802860f8();
  return;
}

