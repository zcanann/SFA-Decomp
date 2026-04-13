// Function: FUN_8000a848
// Entry: 8000a848
// Size: 1632 bytes

/* WARNING: Removing unreachable block (ram,0x8000adec) */

void FUN_8000a848(void)

{
  bool bVar1;
  bool bVar2;
  ushort uVar3;
  bool bVar4;
  undefined4 *puVar5;
  int iVar6;
  int iVar7;
  ushort *puVar8;
  int iVar9;
  uint uVar10;
  byte bVar11;
  int iVar12;
  uint uVar13;
  uint uVar14;
  uint uVar15;
  uint uVar16;
  uint uVar17;
  uint uVar18;
  uint uVar19;
  
  FUN_80286820();
  uVar19 = 0x7fff;
  uVar18 = 0;
  uVar17 = 0;
  uVar16 = 500;
  uVar15 = 500;
  uVar13 = 500;
  bVar2 = false;
  bVar4 = false;
  iVar6 = FUN_8000cf98();
  iVar7 = FUN_8000cf78();
  DAT_803dd490 = 0x7fff;
  puVar5 = &DAT_80336a20;
  iVar12 = 0xf;
  do {
    iVar9 = puVar5[3];
    if (((iVar9 != 0) && (iVar9 != 4)) &&
       ((&DAT_803b15b8)[(uint)*(byte *)(puVar5 + 4) * 0x1868] == '\0')) {
      if ((iVar9 == 4) || (iVar9 == 5)) {
        puVar5[3] = 5;
      }
      else {
        FUN_80272d74(puVar5[1]);
        FUN_800238c4(puVar5[2]);
        *puVar5 = 0xffffffff;
        puVar5[1] = 0xffffffff;
        puVar5[2] = 0;
        *(undefined *)(puVar5 + 4) = 0xff;
        puVar5[3] = 0;
        *(undefined2 *)((int)puVar5 + 0x12) = 0;
        puVar5[8] = FLOAT_803df1e0;
      }
    }
    iVar9 = puVar5[3];
    if (iVar9 == 2) {
      puVar5[8] = (float)puVar5[8] + FLOAT_803dc074 / FLOAT_803df1e4;
      if (FLOAT_803df1e8 < (float)puVar5[8]) {
        if ((puVar5[3] == 4) || (puVar5[3] == 5)) {
          puVar5[3] = 5;
        }
        else {
          FUN_80272d74(puVar5[1]);
          FUN_800238c4(puVar5[2]);
          *puVar5 = 0xffffffff;
          puVar5[1] = 0xffffffff;
          puVar5[2] = 0;
          *(undefined *)(puVar5 + 4) = 0xff;
          puVar5[3] = 0;
          *(undefined2 *)((int)puVar5 + 0x12) = 0;
          puVar5[8] = FLOAT_803df1e0;
        }
      }
    }
    else if (iVar9 < 2) {
      if (0 < iVar9) {
LAB_8000a958:
        uVar3 = *(ushort *)puVar5[7];
        if (uVar3 == 0xbd) {
LAB_8000a984:
          bVar1 = true;
        }
        else {
          if (uVar3 < 0xbd) {
            if (uVar3 == 0x2b) goto LAB_8000a984;
          }
          else if (uVar3 == 0xeb) goto LAB_8000a984;
          bVar1 = false;
        }
        if (!bVar1) {
          if (*(char *)((int)puVar5 + 0x11) == '\0') {
            if (*(ushort *)((int)puVar5 + 0x12) < uVar19) {
              uVar19 = (uint)*(ushort *)((int)puVar5 + 0x12);
            }
          }
          else if ((int)(uint)*(ushort *)((int)puVar5 + 0x12) < (int)DAT_803dd490) {
            DAT_803dd490 = (uint)*(ushort *)((int)puVar5 + 0x12);
          }
        }
      }
    }
    else if (iVar9 < 5) goto LAB_8000a958;
    puVar5 = puVar5 + 9;
    bVar1 = iVar12 != 0;
    iVar12 = iVar12 + -1;
  } while (bVar1);
  puVar5 = &DAT_80336a20;
  iVar12 = 0x10;
  uVar10 = 500;
  do {
    iVar9 = puVar5[3];
    uVar14 = uVar10;
    if (iVar9 == 2) {
      if (*(char *)((int)puVar5 + 0x11) == '\0') {
        uVar10 = (uint)*(ushort *)(puVar5[7] + 4);
        if (*(ushort *)(puVar5[7] + 4) < uVar13) {
          uVar10 = uVar13;
        }
        bVar4 = true;
        uVar13 = uVar10;
      }
      else {
        uVar14 = (uint)*(ushort *)(puVar5[7] + 4);
        if (*(ushort *)(puVar5[7] + 4) < uVar10) {
          uVar14 = uVar10;
        }
      }
    }
    else if (iVar9 < 2) {
      if (0 < iVar9) {
LAB_8000aaac:
        puVar8 = (ushort *)puVar5[7];
        uVar3 = *puVar8;
        if (uVar3 == 0xbd) {
LAB_8000aad8:
          bVar1 = true;
        }
        else {
          if (uVar3 < 0xbd) {
            if (uVar3 == 0x2b) goto LAB_8000aad8;
          }
          else if (uVar3 == 0xeb) goto LAB_8000aad8;
          bVar1 = false;
        }
        if (!bVar1) {
          if (*(char *)((int)puVar5 + 0x11) == '\0') {
            if (((*(ushort *)((int)puVar5 + 0x12) == uVar19) &&
                (uVar10 = puVar5[6], uVar17 < uVar10)) &&
               (uVar15 = (uint)puVar8[2], uVar17 = uVar10, iVar9 != 3)) {
              bVar2 = true;
            }
          }
          else if ((*(ushort *)((int)puVar5 + 0x12) == DAT_803dd490) && (uVar18 < (uint)puVar5[6]))
          {
            uVar16 = (uint)puVar8[2];
            uVar18 = puVar5[6];
          }
        }
      }
    }
    else if (iVar9 < 5) goto LAB_8000aaac;
    puVar5 = puVar5 + 9;
    iVar12 = iVar12 + -1;
    uVar10 = uVar14;
  } while (iVar12 != 0);
  if (bVar2) {
    uVar16 = uVar15;
  }
  if (bVar4) {
    uVar14 = uVar13;
  }
  if ((iVar6 != 0) && (499 < uVar16)) {
    uVar16 = 500;
  }
  if ((iVar7 != 0) && (499 < uVar15)) {
    uVar15 = 500;
  }
  puVar5 = &DAT_80336a20;
  iVar12 = 0xf;
  do {
    iVar9 = puVar5[3];
    if (iVar9 != 2) {
      if (iVar9 < 2) {
        if (0 < iVar9) {
LAB_8000ac10:
          if (*(char *)((int)puVar5 + 0x11) == '\0') {
            uVar10 = (uint)*(ushort *)((int)puVar5 + 0x12);
            if ((uVar10 == uVar19) && ((uint)puVar5[6] < uVar17)) {
              if (iVar9 != 2) {
                if ((iVar9 == 4) || (iVar9 == 5)) {
                  puVar5[3] = 5;
                }
                else {
                  uVar10 = uVar15;
                  if (uVar15 < 500) {
                    uVar10 = 500;
                  }
                  FUN_80272e84(0,uVar10,puVar5[1],1);
                  puVar5[3] = 2;
                }
              }
            }
            else if ((uVar19 < uVar10) || (((int)DAT_803dd490 < (int)uVar10 || (iVar7 != 0)))) {
              if (iVar9 != 3) {
                uVar10 = uVar15;
                if (uVar15 < 500) {
                  uVar10 = 500;
                }
                FUN_80272e84(0,uVar10,puVar5[1],2);
                puVar5[3] = 3;
              }
            }
            else if (iVar9 != 1) {
              FUN_80272e2c(puVar5[1],0xffffffff,0xffffffff);
              FUN_80272df4(puVar5[1]);
              uVar10 = uVar13;
              if (uVar13 < 500) {
                uVar10 = 500;
              }
              FUN_80272e84(*(ushort *)(puVar5 + 5) & 0xff,uVar10,puVar5[1],0);
              puVar5[3] = 1;
            }
          }
          else {
            uVar10 = (uint)*(ushort *)((int)puVar5 + 0x12);
            if ((uVar10 == DAT_803dd490) && ((uint)puVar5[6] < uVar18)) {
              if (iVar9 != 2) {
                if ((iVar9 == 4) || (iVar9 == 5)) {
                  puVar5[3] = 5;
                }
                else {
                  uVar10 = uVar16;
                  if (uVar16 < 500) {
                    uVar10 = 500;
                  }
                  FUN_80272e84(0,uVar10,puVar5[1],1);
                  puVar5[3] = 2;
                }
              }
            }
            else if (((int)DAT_803dd490 < (int)uVar10) || ((uVar19 < uVar10 || (iVar6 != 0)))) {
              if (iVar9 != 3) {
                if (*(char *)((int)puVar5 + 0x11) == '\0') {
                  bVar11 = 2;
                }
                else {
                  bVar11 = 0;
                }
                uVar10 = uVar16;
                if (uVar16 < 500) {
                  uVar10 = 500;
                }
                FUN_80272e84(0,uVar10,puVar5[1],bVar11);
                puVar5[3] = 3;
              }
            }
            else if (iVar9 != 1) {
              FUN_80272e2c(puVar5[1],0xffffffff,0xffffffff);
              FUN_80272df4(puVar5[1]);
              uVar10 = uVar14;
              if (uVar14 < 500) {
                uVar10 = 500;
              }
              FUN_80272e84(*(ushort *)(puVar5 + 5) & 0xff,uVar10,puVar5[1],0);
              puVar5[3] = 1;
            }
          }
        }
      }
      else if (iVar9 < 4) goto LAB_8000ac10;
    }
    puVar5 = puVar5 + 9;
    bVar2 = iVar12 == 0;
    iVar12 = iVar12 + -1;
    if (bVar2) {
      FUN_8028686c();
      return;
    }
  } while( true );
}

