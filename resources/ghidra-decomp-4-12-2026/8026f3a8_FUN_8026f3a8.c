// Function: FUN_8026f3a8
// Entry: 8026f3a8
// Size: 1736 bytes

void FUN_8026f3a8(int param_1)

{
  bool bVar1;
  undefined4 uVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  uint *puVar8;
  int *piVar9;
  int *piVar10;
  int *piVar11;
  int *piVar12;
  int iVar13;
  double dVar14;
  double dVar15;
  double dVar16;
  double dVar17;
  double dVar18;
  double dVar19;
  double dVar20;
  double dVar21;
  undefined8 uVar22;
  undefined8 local_78;
  
  if (param_1 != 0) {
    dVar18 = (double)FLOAT_803e8420;
    dVar19 = ABS(dVar18);
    dVar20 = (double)FLOAT_803e8418;
    dVar17 = (double)FLOAT_803e841c;
    piVar11 = DAT_803deeb4;
    dVar21 = DOUBLE_803e8428;
    piVar9 = DAT_803deeac;
    while (DAT_803deeac = piVar9, piVar12 = piVar11, piVar12 != (int *)0x0) {
      piVar11 = (int *)*piVar12;
      DAT_803deea0 = (uint)*(byte *)((int)piVar12 + 9);
      DAT_803dee98 = piVar12;
      uVar2 = FUN_802726c0((uint)*(byte *)(piVar12 + 0x3ac));
      piVar9 = DAT_803dee98;
      DAT_803deea4 = (undefined)uVar2;
      if (DAT_803dee98[0x539] == 0) {
        if (DAT_803dee98[0x53a] != 0) {
          while ((puVar8 = (uint *)piVar9[0x53b], *puVar8 != 0xffffffff &&
                 (*puVar8 <= (uint)piVar9[(uint)*(byte *)(piVar9 + 0x546) * 2 + 0x543]))) {
            if ((*(uint *)(DAT_803dee98[0x46] + 0x10) & 0x40000000) == 0) {
              FUN_8026fca0(puVar8[1],(byte)DAT_803deea0,0);
              piVar9[0x53c] = *(int *)(piVar9[0x53b] + 4) << 10;
            }
            else {
              uVar4 = puVar8[1];
              piVar9[0x53c] = uVar4;
              FUN_8026fca0(uVar4 >> 10,(byte)DAT_803deea0,0);
            }
            piVar9[0x53b] = piVar9[0x53b] + 8;
          }
        }
        piVar9 = DAT_803dee98;
        local_78 = (double)CONCAT44(0x43300000,(uint)*(ushort *)((int)DAT_803dee98 + 0x151a));
        dVar16 = (double)((float)(dVar20 * (double)((float)((double)CONCAT44(0x43300000,
                                                                             DAT_803dee98[0x53c]) -
                                                           dVar21) *
                                                   (float)((double)CONCAT44(0x43300000,param_1) -
                                                          dVar21))) *
                         (float)(dVar17 * (double)(float)(local_78 - dVar21)));
        dVar15 = (double)(float)(dVar18 * dVar16);
        if (dVar19 <= ABS(dVar15)) {
          uVar22 = FUN_80286d70((ulonglong)(double)(float)(dVar15 / dVar18));
          dVar14 = FUN_80286c1c((uint)((ulonglong)uVar22 >> 0x20),(uint)uVar22);
          dVar15 = (double)(float)(dVar15 - (double)(float)(dVar18 * dVar14));
        }
        iVar3 = FUN_80286718(dVar15);
        piVar9[(uint)*(byte *)(piVar9 + 0x546) * 2 + 0x53d] = iVar3;
        dVar15 = FUN_80294e84(dVar16);
        piVar9[(uint)*(byte *)(piVar9 + 0x546) * 2 + 0x53e] = (int)dVar15;
        uVar4 = FUN_8026f134(0,param_1);
        iVar3 = FUN_8026c888();
        if (*(char *)((int)DAT_803dee98 + 0xee2) == '\0') {
          piVar9 = (int *)DAT_803dee98[0x39b];
          while (piVar10 = piVar9, piVar10 != (int *)0x0) {
            piVar9 = (int *)*piVar10;
            if ((piVar10[2] != 0xffffffff) &&
               (uVar7 = FUN_80273090(piVar10[2]), uVar7 == 0xffffffff)) {
              FUN_8026ca84(piVar10);
            }
          }
        }
        uVar7 = *(byte *)((int)DAT_803dee98 + 0xee2) + 1;
        *(char *)((int)DAT_803dee98 + 0xee2) = (char)uVar7 + (char)(uVar7 / 5) * -5;
        piVar9 = DAT_803dee98 + 0x53d;
        iVar5 = DAT_803dee98[0x542];
        DAT_803dee98[0x542] = iVar5 + *piVar9 & 0xffff;
        DAT_803dee98[0x543] =
             ((uint)(iVar5 + *piVar9) >> 0x10) + DAT_803dee98[0x53e] + DAT_803dee98[0x543];
        piVar9 = DAT_803dee98 + 0x53f;
        iVar5 = DAT_803dee98[0x544];
        DAT_803dee98[0x544] = iVar5 + *piVar9 & 0xffff;
        DAT_803dee98[0x545] =
             ((uint)(iVar5 + *piVar9) >> 0x10) + DAT_803dee98[0x540] + DAT_803dee98[0x545];
      }
      else {
        uVar4 = 0;
        uVar7 = 0;
        iVar3 = 0;
        do {
          piVar9 = DAT_803dee98 + (uVar7 & 0xff) * 0xe + 0x53a;
          if (*piVar9 != 0) {
            while ((puVar8 = (uint *)piVar9[1], *puVar8 != 0xffffffff &&
                   (*puVar8 <= (uint)piVar9[(uint)*(byte *)(piVar9 + 0xc) * 2 + 9]))) {
              if ((*(uint *)(DAT_803dee98[0x46] + 0x10) & 0x40000000) == 0) {
                FUN_8026fca0(puVar8[1],(byte)DAT_803deea0,uVar7 & 0xff);
                piVar9[2] = *(int *)(piVar9[1] + 4) << 10;
              }
              else {
                uVar6 = puVar8[1];
                piVar9[2] = uVar6;
                FUN_8026fca0(uVar6 >> 10,(byte)DAT_803deea0,uVar7 & 0xff);
              }
              piVar9[1] = piVar9[1] + 8;
            }
          }
          piVar9 = DAT_803dee98;
          local_78 = (double)CONCAT44(0x43300000,*(undefined4 *)((int)DAT_803dee98 + iVar3 + 0x14f0)
                                     );
          dVar16 = (double)((float)(dVar20 * (double)((float)(local_78 - dVar21) *
                                                     (float)((double)CONCAT44(0x43300000,param_1) -
                                                            dVar21))) *
                           (float)(dVar17 * (double)(float)((double)CONCAT44(0x43300000,
                                                                             (uint)*(ushort *)
                                                                                    ((int)
                                                  DAT_803dee98 + iVar3 + 0x151a)) - dVar21)));
          dVar15 = (double)(float)(dVar18 * dVar16);
          if (dVar19 <= ABS(dVar15)) {
            uVar22 = FUN_80286d70((ulonglong)(double)(float)(dVar15 / dVar18));
            dVar14 = FUN_80286c1c((uint)((ulonglong)uVar22 >> 0x20),(uint)uVar22);
            dVar15 = (double)(float)(dVar15 - (double)(float)(dVar18 * dVar14));
          }
          iVar5 = FUN_80286718(dVar15);
          *(int *)((int)piVar9 +
                  (uint)*(byte *)((int)piVar9 + iVar3 + 0x1518) * 8 + 0xc + iVar3 + 0x14e8) = iVar5;
          dVar15 = FUN_80294e84(dVar16);
          *(int *)((int)piVar9 +
                  (uint)*(byte *)((int)piVar9 + iVar3 + 0x1518) * 8 + 0x10 + iVar3 + 0x14e8) =
               (int)dVar15;
          uVar6 = FUN_8026f134(uVar7 & 0xff,param_1);
          uVar7 = uVar7 + 1;
          uVar4 = uVar4 | uVar6;
          iVar3 = iVar3 + 0x38;
        } while (uVar7 < 0x10);
        iVar3 = FUN_8026c888();
        if (*(char *)((int)DAT_803dee98 + 0xee2) == '\0') {
          piVar9 = (int *)DAT_803dee98[0x39b];
          while (piVar10 = piVar9, piVar10 != (int *)0x0) {
            piVar9 = (int *)*piVar10;
            if ((piVar10[2] != 0xffffffff) &&
               (uVar7 = FUN_80273090(piVar10[2]), uVar7 == 0xffffffff)) {
              FUN_8026ca84(piVar10);
            }
          }
        }
        iVar13 = 8;
        uVar7 = *(byte *)((int)DAT_803dee98 + 0xee2) + 1;
        *(char *)((int)DAT_803dee98 + 0xee2) = (char)uVar7 + (char)(uVar7 / 5) * -5;
        iVar5 = 0;
        do {
          uVar7 = *(int *)((int)DAT_803dee98 + iVar5 + 0x1508) +
                  *(int *)((int)DAT_803dee98 + iVar5 + 0x14f4);
          *(uint *)((int)DAT_803dee98 + iVar5 + 0x1508) = uVar7 & 0xffff;
          *(uint *)((int)DAT_803dee98 + iVar5 + 0x150c) =
               (uVar7 >> 0x10) +
               *(int *)((int)DAT_803dee98 + iVar5 + 0x14f8) +
               *(int *)((int)DAT_803dee98 + iVar5 + 0x150c);
          uVar7 = *(int *)((int)DAT_803dee98 + iVar5 + 0x1510) +
                  *(int *)((int)DAT_803dee98 + iVar5 + 0x14fc);
          *(uint *)((int)DAT_803dee98 + iVar5 + 0x1510) = uVar7 & 0xffff;
          *(uint *)((int)DAT_803dee98 + iVar5 + 0x1514) =
               (uVar7 >> 0x10) +
               *(int *)((int)DAT_803dee98 + iVar5 + 0x1500) +
               *(int *)((int)DAT_803dee98 + iVar5 + 0x1514);
          uVar7 = *(int *)((int)DAT_803dee98 + iVar5 + 0x1540) +
                  *(int *)((int)DAT_803dee98 + iVar5 + 0x152c);
          *(uint *)((int)DAT_803dee98 + iVar5 + 0x1540) = uVar7 & 0xffff;
          *(uint *)((int)DAT_803dee98 + iVar5 + 0x1544) =
               (uVar7 >> 0x10) +
               *(int *)((int)DAT_803dee98 + iVar5 + 0x1530) +
               *(int *)((int)DAT_803dee98 + iVar5 + 0x1544);
          uVar7 = *(int *)((int)DAT_803dee98 + iVar5 + 0x1548) +
                  *(int *)((int)DAT_803dee98 + iVar5 + 0x1534);
          *(uint *)((int)DAT_803dee98 + iVar5 + 0x1548) = uVar7 & 0xffff;
          *(uint *)((int)DAT_803dee98 + iVar5 + 0x154c) =
               (uVar7 >> 0x10) +
               *(int *)((int)DAT_803dee98 + iVar5 + 0x1538) +
               *(int *)((int)DAT_803dee98 + iVar5 + 0x154c);
          iVar13 = iVar13 + -1;
          iVar5 = iVar5 + 0x70;
        } while (iVar13 != 0);
      }
      piVar9 = DAT_803deeac;
      if ((uVar4 == 0) && (iVar3 == 0)) {
        piVar9 = piVar11;
        if ((undefined4 *)piVar12[1] != (undefined4 *)0x0) {
          *(undefined4 *)piVar12[1] = piVar11;
          piVar9 = DAT_803deeb4;
        }
        DAT_803deeb4 = piVar9;
        if (piVar11 != (int *)0x0) {
          piVar11[1] = piVar12[1];
        }
        FUN_8026c6b8((int)piVar12);
        *(undefined *)(piVar12 + 2) = 0;
        piVar12[1] = 0;
        bVar1 = DAT_803deeac != (int *)0x0;
        *piVar12 = (int)DAT_803deeac;
        piVar9 = piVar12;
        if (bVar1) {
          *(int **)((int)DAT_803deeac + 4) = piVar12;
        }
      }
    }
  }
  return;
}

