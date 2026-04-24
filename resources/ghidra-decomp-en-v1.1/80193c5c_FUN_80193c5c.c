// Function: FUN_80193c5c
// Entry: 80193c5c
// Size: 1500 bytes

/* WARNING: Removing unreachable block (ram,0x80194218) */
/* WARNING: Removing unreachable block (ram,0x80193c6c) */

void FUN_80193c5c(void)

{
  byte bVar1;
  float fVar2;
  bool bVar3;
  float fVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  ushort *puVar8;
  ushort *puVar9;
  uint uVar10;
  int iVar11;
  int iVar12;
  short *psVar13;
  int iVar14;
  int *piVar15;
  int iVar16;
  int iVar17;
  int iVar18;
  int *piVar19;
  int iVar20;
  int iVar21;
  double in_f31;
  double dVar22;
  double in_ps31_1;
  float local_78;
  float fStack_74;
  float local_70;
  undefined4 local_68;
  uint uStack_64;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar5 = FUN_80286810();
  FUN_8002bac4();
  piVar15 = *(int **)(uVar5 + 0xb8);
  iVar14 = *(int *)(uVar5 + 0x4c);
  if (*(char *)(iVar14 + 0x25) != '\0') {
    iVar6 = FUN_8005b478((double)*(float *)(uVar5 + 0xc),(double)*(float *)(uVar5 + 0x10));
    iVar6 = (int)(char)iVar6;
    bVar1 = *(byte *)((int)piVar15 + 0x2d);
    if (iVar6 < 0) {
      *(byte *)((int)piVar15 + 0x2d) = bVar1 & 0xfe;
    }
    else {
      *(byte *)((int)piVar15 + 0x2d) = bVar1 | 1;
    }
    if ((*(byte *)((int)piVar15 + 0x2d) & 1) != (bVar1 & 1)) {
      *(undefined *)(piVar15 + 0xb) = 2;
    }
    bVar3 = (*(byte *)((int)piVar15 + 0x2d) & 1) != 0;
    if (bVar3) {
      if ((bVar3) && (*piVar15 == 0)) {
        iVar7 = FUN_8005b068(iVar6);
        iVar7 = FUN_80060804(iVar7,(uint)*(byte *)(iVar14 + 0x25));
        *(short *)(piVar15 + 10) = (short)iVar7 * 3;
        if (0 < *(short *)(piVar15 + 10)) {
          iVar7 = FUN_80023d8c(*(short *)(piVar15 + 10) * 6,5);
          *piVar15 = iVar7;
          piVar15[1] = iVar7 + *(short *)(piVar15 + 10) * 4;
          FUN_80193844(uVar5,piVar15,iVar14);
        }
      }
      if (*(short *)(piVar15 + 10) != 0) {
        if (*(char *)(iVar14 + 0x22) == '\0') {
          if (piVar15[2] == 0) {
            local_78 = FLOAT_803e4c30;
            iVar7 = FUN_80036f50(4,uVar5,&local_78);
            piVar15[2] = iVar7;
            iVar7 = piVar15[2];
            if (iVar7 != 0) {
              if (*(short *)(iVar7 + 0x46) == 0x519) {
                if ((*(byte *)((int)piVar15 + 0x2d) & 2) == 0) {
                  FUN_801a86a4(iVar7,'\x01');
                }
                FUN_801a8678((double)*(float *)(uVar5 + 0xc),
                             (double)(*(float *)(uVar5 + 0x10) - (float)piVar15[6]),
                             (double)*(float *)(uVar5 + 0x14),iVar7);
              }
              else {
                if ((*(byte *)((int)piVar15 + 0x2d) & 2) == 0) {
                  (**(code **)(**(int **)(iVar7 + 0x68) + 0x24))(iVar7,1);
                }
                (**(code **)(**(int **)(iVar7 + 0x68) + 0x38))
                          ((double)*(float *)(uVar5 + 0xc),
                           (double)(*(float *)(uVar5 + 0x10) - (float)piVar15[6]),
                           (double)*(float *)(uVar5 + 0x14),iVar7);
              }
            }
          }
          else if ((*(ushort *)(piVar15[2] + 0xb0) & 0x40) != 0) {
            piVar15[2] = 0;
          }
        }
        iVar6 = FUN_8005b068(iVar6);
        fVar4 = FLOAT_803e4c48;
        if ((iVar6 != 0) && ((*(ushort *)(iVar6 + 4) & 8) != 0)) {
          fVar2 = (float)piVar15[3];
          if (FLOAT_803e4c48 < fVar2) {
            if ((*(byte *)((int)piVar15 + 0x2d) & 4) == 0) {
              uStack_64 = (uint)*(byte *)(iVar14 + 0x20);
              local_68 = 0x43300000;
              if ((fVar2 < FLOAT_803e4c30 *
                           (float)((double)CONCAT44(0x43300000,uStack_64) - DOUBLE_803e4c38)) &&
                 (piVar15[3] = (int)(fVar2 - FLOAT_803dc074), (float)piVar15[3] < fVar4)) {
                piVar15[3] = (int)fVar4;
              }
            }
            else {
              *(byte *)((int)piVar15 + 0x2d) = *(byte *)((int)piVar15 + 0x2d) & 0xfb;
            }
            if ((float)piVar15[3] != (float)piVar15[4]) {
              *(undefined *)(piVar15 + 0xb) = 2;
              piVar15[4] = piVar15[3];
            }
            if (*(char *)(piVar15 + 0xb) != '\0') {
              *(char *)(piVar15 + 0xb) = *(char *)(piVar15 + 0xb) + -1;
              uStack_64 = (uint)*(byte *)(iVar14 + 0x20);
              local_68 = 0x43300000;
              fVar4 = FLOAT_803e4c30 *
                      (float)((double)CONCAT44(0x43300000,uStack_64) - DOUBLE_803e4c38);
              if (fVar4 < (float)piVar15[4]) {
                piVar15[4] = (int)fVar4;
                piVar15[3] = (int)fVar4;
                iVar7 = piVar15[2];
                if ((iVar7 != 0) && (*(int *)(iVar7 + 0xb8) != 0)) {
                  if (*(short *)(iVar7 + 0x46) == 0x519) {
                    FUN_801a86a4(iVar7,'\0');
                  }
                  else {
                    (**(code **)(**(int **)(iVar7 + 0x68) + 0x24))(iVar7,0);
                  }
                }
                FUN_800201ac((int)*(short *)(iVar14 + 0x18),1);
                *(byte *)((int)piVar15 + 0x2d) = *(byte *)((int)piVar15 + 0x2d) | 2;
                FUN_8000bb38(uVar5,*(ushort *)(&DAT_803dca58 + (uint)*(byte *)(iVar14 + 0x21) * 2));
              }
              iVar18 = 0;
              iVar17 = 0;
              dVar22 = (double)FLOAT_803e4c48;
              piVar19 = piVar15;
              for (iVar7 = 0; iVar7 < (int)(uint)*(byte *)((int)piVar15 + 0x2a); iVar7 = iVar7 + 1)
              {
                puVar8 = (ushort *)FUN_80060868(iVar6,(int)*(short *)(piVar19 + 7));
                iVar11 = iVar17;
                iVar12 = iVar18;
                for (uVar10 = (uint)*puVar8; (int)uVar10 < (int)(uint)puVar8[10];
                    uVar10 = uVar10 + 1) {
                  puVar9 = (ushort *)FUN_80060858(iVar6,uVar10);
                  iVar16 = 0;
                  iVar20 = iVar11;
                  iVar21 = iVar12;
                  do {
                    if (dVar22 < (double)*(float *)(*piVar15 + iVar12)) {
                      psVar13 = (short *)(*(int *)(iVar6 + 0x58) + (uint)*puVar9 * 6);
                      FUN_8006076c(psVar13,&fStack_74);
                      uStack_64 = (int)*(short *)(piVar15[1] + iVar11) ^ 0x80000000;
                      local_68 = 0x43300000;
                      local_70 = (float)((double)CONCAT44(0x43300000,uStack_64) - DOUBLE_803e4c60) -
                                 ((float)piVar15[4] / FLOAT_803e4c30) *
                                 *(float *)(*piVar15 + iVar12);
                      FUN_80060708(psVar13,&fStack_74);
                    }
                    iVar12 = iVar12 + 4;
                    iVar11 = iVar11 + 2;
                    iVar21 = iVar21 + 4;
                    iVar20 = iVar20 + 2;
                    iVar18 = iVar18 + 4;
                    iVar17 = iVar17 + 2;
                    puVar9 = puVar9 + 1;
                    iVar16 = iVar16 + 1;
                  } while (iVar16 < 3);
                  iVar11 = iVar20;
                  iVar12 = iVar21;
                }
                piVar19 = (int *)((int)piVar19 + 2);
              }
              FUN_80242178(*(uint *)(iVar6 + 0x58),(uint)*(ushort *)(iVar6 + 0x90) * 6);
            }
          }
          if (((int)*(short *)(iVar14 + 0x1a) == 0xffffffff) ||
             (uVar10 = FUN_80020078((int)*(short *)(iVar14 + 0x1a)), uVar10 != 0)) {
            bVar3 = true;
          }
          else {
            bVar3 = false;
          }
          if (((*(byte *)((int)piVar15 + 0x2d) & 2) == 0) && (bVar3)) {
            iVar14 = FUN_8002ba84();
            if ((iVar14 == 0) || (uVar10 = FUN_80020078(0x4e4), uVar10 == 0)) {
              *(byte *)(uVar5 + 0xaf) = *(byte *)(uVar5 + 0xaf) | 0x10;
            }
            else {
              *(byte *)(uVar5 + 0xaf) = *(byte *)(uVar5 + 0xaf) & 0xef;
            }
            *(byte *)(uVar5 + 0xaf) = *(byte *)(uVar5 + 0xaf) & 0xf7;
            if ((iVar14 != 0) && ((*(byte *)(uVar5 + 0xaf) & 4) != 0)) {
              (**(code **)(**(int **)(iVar14 + 0x68) + 0x28))(iVar14,uVar5,1,1);
            }
          }
          else {
            *(byte *)(uVar5 + 0xaf) = *(byte *)(uVar5 + 0xaf) | 8;
          }
          FUN_80041110();
        }
      }
    }
  }
  FUN_8028685c();
  return;
}

