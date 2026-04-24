// Function: FUN_8000a828
// Entry: 8000a828
// Size: 1632 bytes

/* WARNING: Removing unreachable block (ram,0x8000adcc) */

void FUN_8000a828(void)

{
  bool bVar1;
  bool bVar2;
  bool bVar3;
  undefined4 *puVar4;
  ushort uVar5;
  int iVar6;
  int iVar7;
  ushort *puVar8;
  int iVar9;
  uint uVar10;
  undefined4 uVar11;
  int iVar12;
  ushort uVar13;
  ushort uVar14;
  ushort uVar15;
  ushort uVar16;
  uint uVar17;
  uint uVar18;
  uint uVar19;
  
  FUN_802860bc();
  uVar19 = 0x7fff;
  uVar18 = 0;
  uVar17 = 0;
  uVar16 = 500;
  uVar15 = 500;
  uVar14 = 500;
  uVar13 = 500;
  bVar2 = false;
  bVar3 = false;
  iVar6 = FUN_8000cf78();
  iVar7 = FUN_8000cf58();
  DAT_803dc810 = 0x7fff;
  puVar4 = &DAT_80335dc0;
  iVar12 = 0xf;
  do {
    iVar9 = puVar4[3];
    if (((iVar9 != 0) && (iVar9 != 4)) &&
       ((&DAT_803b0958)[(uint)*(byte *)(puVar4 + 4) * 0x1868] == '\0')) {
      if ((iVar9 == 4) || (iVar9 == 5)) {
        puVar4[3] = 5;
      }
      else {
        FUN_80272610(puVar4[1]);
        FUN_80023800(puVar4[2]);
        *puVar4 = 0xffffffff;
        puVar4[1] = 0xffffffff;
        puVar4[2] = 0;
        *(undefined *)(puVar4 + 4) = 0xff;
        puVar4[3] = 0;
        *(undefined2 *)((int)puVar4 + 0x12) = 0;
        puVar4[8] = FLOAT_803de560;
      }
    }
    iVar9 = puVar4[3];
    if (iVar9 == 2) {
      puVar4[8] = (float)puVar4[8] + FLOAT_803db414 / FLOAT_803de564;
      if (FLOAT_803de568 < (float)puVar4[8]) {
        if ((puVar4[3] == 4) || (puVar4[3] == 5)) {
          puVar4[3] = 5;
        }
        else {
          FUN_80272610(puVar4[1]);
          FUN_80023800(puVar4[2]);
          *puVar4 = 0xffffffff;
          puVar4[1] = 0xffffffff;
          puVar4[2] = 0;
          *(undefined *)(puVar4 + 4) = 0xff;
          puVar4[3] = 0;
          *(undefined2 *)((int)puVar4 + 0x12) = 0;
          puVar4[8] = FLOAT_803de560;
        }
      }
    }
    else if (iVar9 < 2) {
      if (0 < iVar9) {
LAB_8000a938:
        uVar5 = *(ushort *)puVar4[7];
        if (uVar5 == 0xbd) {
LAB_8000a964:
          bVar1 = true;
        }
        else {
          if (uVar5 < 0xbd) {
            if (uVar5 == 0x2b) goto LAB_8000a964;
          }
          else if (uVar5 == 0xeb) goto LAB_8000a964;
          bVar1 = false;
        }
        if (!bVar1) {
          if (*(char *)((int)puVar4 + 0x11) == '\0') {
            if (*(ushort *)((int)puVar4 + 0x12) < uVar19) {
              uVar19 = (uint)*(ushort *)((int)puVar4 + 0x12);
            }
          }
          else if ((int)(uint)*(ushort *)((int)puVar4 + 0x12) < (int)DAT_803dc810) {
            DAT_803dc810 = (uint)*(ushort *)((int)puVar4 + 0x12);
          }
        }
      }
    }
    else if (iVar9 < 5) goto LAB_8000a938;
    puVar4 = puVar4 + 9;
    bVar1 = iVar12 != 0;
    iVar12 = iVar12 + -1;
  } while (bVar1);
  puVar4 = &DAT_80335dc0;
  iVar12 = 0x10;
  do {
    iVar9 = puVar4[3];
    uVar5 = uVar14;
    if (iVar9 == 2) {
      if (*(char *)((int)puVar4 + 0x11) == '\0') {
        uVar14 = *(ushort *)(puVar4[7] + 4);
        if (*(ushort *)(puVar4[7] + 4) < uVar13) {
          uVar14 = uVar13;
        }
        uVar13 = uVar14;
        bVar3 = true;
      }
      else {
        uVar5 = *(ushort *)(puVar4[7] + 4);
        if (*(ushort *)(puVar4[7] + 4) < uVar14) {
          uVar5 = uVar14;
        }
      }
    }
    else if (iVar9 < 2) {
      if (0 < iVar9) {
LAB_8000aa8c:
        puVar8 = (ushort *)puVar4[7];
        uVar14 = *puVar8;
        if (uVar14 == 0xbd) {
LAB_8000aab8:
          bVar1 = true;
        }
        else {
          if (uVar14 < 0xbd) {
            if (uVar14 == 0x2b) goto LAB_8000aab8;
          }
          else if (uVar14 == 0xeb) goto LAB_8000aab8;
          bVar1 = false;
        }
        if (!bVar1) {
          if (*(char *)((int)puVar4 + 0x11) == '\0') {
            if (((*(ushort *)((int)puVar4 + 0x12) == uVar19) &&
                (uVar10 = puVar4[6], uVar17 < uVar10)) &&
               (uVar15 = puVar8[2], uVar17 = uVar10, iVar9 != 3)) {
              bVar2 = true;
            }
          }
          else if ((*(ushort *)((int)puVar4 + 0x12) == DAT_803dc810) && (uVar18 < (uint)puVar4[6]))
          {
            uVar16 = puVar8[2];
            uVar18 = puVar4[6];
          }
        }
      }
    }
    else if (iVar9 < 5) goto LAB_8000aa8c;
    uVar14 = uVar5;
    puVar4 = puVar4 + 9;
    iVar12 = iVar12 + -1;
  } while (iVar12 != 0);
  if (bVar2) {
    uVar16 = uVar15;
  }
  if (bVar3) {
    uVar14 = uVar13;
  }
  if ((iVar6 != 0) && (499 < uVar16)) {
    uVar16 = 500;
  }
  if ((iVar7 != 0) && (499 < uVar15)) {
    uVar15 = 500;
  }
  puVar4 = &DAT_80335dc0;
  iVar12 = 0xf;
  do {
    iVar9 = puVar4[3];
    if (iVar9 != 2) {
      if (iVar9 < 2) {
        if (0 < iVar9) {
LAB_8000abf0:
          if (*(char *)((int)puVar4 + 0x11) == '\0') {
            uVar10 = (uint)*(ushort *)((int)puVar4 + 0x12);
            if ((uVar10 == uVar19) && ((uint)puVar4[6] < uVar17)) {
              if (iVar9 != 2) {
                if ((iVar9 == 4) || (iVar9 == 5)) {
                  puVar4[3] = 5;
                }
                else {
                  uVar5 = uVar15;
                  if (uVar15 < 500) {
                    uVar5 = 500;
                  }
                  FUN_80272720(0,uVar5,puVar4[1],1);
                  puVar4[3] = 2;
                }
              }
            }
            else if ((uVar19 < uVar10) || (((int)DAT_803dc810 < (int)uVar10 || (iVar7 != 0)))) {
              if (iVar9 != 3) {
                uVar5 = uVar15;
                if (uVar15 < 500) {
                  uVar5 = 500;
                }
                FUN_80272720(0,uVar5,puVar4[1],2);
                puVar4[3] = 3;
              }
            }
            else if (iVar9 != 1) {
              FUN_802726c8(puVar4[1],0xffffffff,0xffffffff);
              FUN_80272690(puVar4[1]);
              uVar5 = uVar13;
              if (uVar13 < 500) {
                uVar5 = 500;
              }
              FUN_80272720(*(ushort *)(puVar4 + 5) & 0xff,uVar5,puVar4[1],0);
              puVar4[3] = 1;
            }
          }
          else {
            uVar10 = (uint)*(ushort *)((int)puVar4 + 0x12);
            if ((uVar10 == DAT_803dc810) && ((uint)puVar4[6] < uVar18)) {
              if (iVar9 != 2) {
                if ((iVar9 == 4) || (iVar9 == 5)) {
                  puVar4[3] = 5;
                }
                else {
                  uVar5 = uVar16;
                  if (uVar16 < 500) {
                    uVar5 = 500;
                  }
                  FUN_80272720(0,uVar5,puVar4[1],1);
                  puVar4[3] = 2;
                }
              }
            }
            else if (((int)DAT_803dc810 < (int)uVar10) || ((uVar19 < uVar10 || (iVar6 != 0)))) {
              if (iVar9 != 3) {
                if (*(char *)((int)puVar4 + 0x11) == '\0') {
                  uVar11 = 2;
                }
                else {
                  uVar11 = 0;
                }
                uVar5 = uVar16;
                if (uVar16 < 500) {
                  uVar5 = 500;
                }
                FUN_80272720(0,uVar5,puVar4[1],uVar11);
                puVar4[3] = 3;
              }
            }
            else if (iVar9 != 1) {
              FUN_802726c8(puVar4[1],0xffffffff,0xffffffff);
              FUN_80272690(puVar4[1]);
              uVar5 = uVar14;
              if (uVar14 < 500) {
                uVar5 = 500;
              }
              FUN_80272720(*(ushort *)(puVar4 + 5) & 0xff,uVar5,puVar4[1],0);
              puVar4[3] = 1;
            }
          }
        }
      }
      else if (iVar9 < 4) goto LAB_8000abf0;
    }
    puVar4 = puVar4 + 9;
    bVar2 = iVar12 == 0;
    iVar12 = iVar12 + -1;
    if (bVar2) {
      FUN_80286108();
      return;
    }
  } while( true );
}

