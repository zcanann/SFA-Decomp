// Function: FUN_8026ec44
// Entry: 8026ec44
// Size: 1736 bytes

void FUN_8026ec44(int param_1)

{
  bool bVar1;
  int *piVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  uint uVar7;
  uint uVar8;
  int **ppiVar9;
  int **ppiVar10;
  int **ppiVar11;
  int **ppiVar12;
  int iVar13;
  double dVar14;
  double dVar15;
  double dVar16;
  double dVar17;
  double dVar18;
  double dVar19;
  double dVar20;
  double dVar21;
  double local_78;
  
  if (param_1 != 0) {
    dVar18 = (double)FLOAT_803e7788;
    dVar19 = ABS(dVar18);
    dVar20 = (double)FLOAT_803e7780;
    dVar17 = (double)FLOAT_803e7784;
    ppiVar11 = DAT_803de234;
    dVar21 = DOUBLE_803e7790;
    ppiVar10 = DAT_803de22c;
    while (DAT_803de22c = ppiVar10, ppiVar12 = ppiVar11, ppiVar12 != (int **)0x0) {
      ppiVar11 = (int **)*ppiVar12;
      DAT_803de220 = (uint)*(byte *)((int)ppiVar12 + 9);
      DAT_803de218 = ppiVar12;
      DAT_803de224 = FUN_80271f5c(*(undefined *)(ppiVar12 + 0x3ac));
      ppiVar10 = DAT_803de218;
      if (DAT_803de218[0x539] == (int *)0x0) {
        if (DAT_803de218[0x53a] != (int *)0x0) {
          while ((ppiVar9 = (int **)ppiVar10[0x53b], *ppiVar9 != (int *)0xffffffff &&
                 (*ppiVar9 <= ppiVar10[(uint)*(byte *)(ppiVar10 + 0x546) * 2 + 0x543]))) {
            if ((DAT_803de218[0x46][4] & 0x40000000U) == 0) {
              FUN_8026f53c(ppiVar9[1],DAT_803de220 & 0xff,0);
              ppiVar10[0x53c] = (int *)(ppiVar10[0x53b][1] << 10);
            }
            else {
              piVar2 = ppiVar9[1];
              ppiVar10[0x53c] = piVar2;
              FUN_8026f53c((uint)piVar2 >> 10,DAT_803de220 & 0xff,0);
            }
            ppiVar10[0x53b] = ppiVar10[0x53b] + 2;
          }
        }
        ppiVar10 = DAT_803de218;
        local_78 = (double)CONCAT44(0x43300000,(uint)*(ushort *)((int)DAT_803de218 + 0x151a));
        dVar16 = (double)((float)(dVar20 * (double)((float)((double)CONCAT44(0x43300000,
                                                                             DAT_803de218[0x53c]) -
                                                           dVar21) *
                                                   (float)((double)CONCAT44(0x43300000,param_1) -
                                                          dVar21))) *
                         (float)(dVar17 * (double)(float)(local_78 - dVar21)));
        dVar15 = (double)(float)(dVar18 * dVar16);
        if (dVar19 <= ABS(dVar15)) {
          FUN_8028660c((double)(float)(dVar15 / dVar18));
          dVar14 = (double)FUN_802864b8();
          dVar15 = (double)(float)(dVar15 - (double)(float)(dVar18 * dVar14));
        }
        piVar2 = (int *)FUN_80285fb4(dVar15);
        ppiVar10[(uint)*(byte *)(ppiVar10 + 0x546) * 2 + 0x53d] = piVar2;
        dVar15 = (double)FUN_80294724(dVar16);
        ppiVar10[(uint)*(byte *)(ppiVar10 + 0x546) * 2 + 0x53e] = (int *)(int)dVar15;
        uVar3 = FUN_8026e9d0(0,param_1);
        iVar4 = FUN_8026c124();
        if (*(char *)((int)DAT_803de218 + 0xee2) == '\0') {
          ppiVar10 = (int **)DAT_803de218[0x39b];
          while (ppiVar9 = ppiVar10, ppiVar9 != (int **)0x0) {
            ppiVar10 = (int **)*ppiVar9;
            if ((ppiVar9[2] != (int *)0xffffffff) && (iVar5 = FUN_8027292c(), iVar5 == -1)) {
              FUN_8026c320(ppiVar9);
            }
          }
        }
        uVar8 = *(byte *)((int)DAT_803de218 + 0xee2) + 1;
        *(char *)((int)DAT_803de218 + 0xee2) = (char)uVar8 + (char)(uVar8 / 5) * -5;
        ppiVar10 = DAT_803de218 + 0x53d;
        piVar2 = DAT_803de218[0x542];
        DAT_803de218[0x542] = (int *)((int)piVar2 + (int)*ppiVar10 & 0xffff);
        DAT_803de218[0x543] =
             (int *)(((uint)((int)piVar2 + (int)*ppiVar10) >> 0x10) +
                    (int)DAT_803de218[0x53e] + (int)DAT_803de218[0x543]);
        ppiVar10 = DAT_803de218 + 0x53f;
        piVar2 = DAT_803de218[0x544];
        DAT_803de218[0x544] = (int *)((int)piVar2 + (int)*ppiVar10 & 0xffff);
        DAT_803de218[0x545] =
             (int *)(((uint)((int)piVar2 + (int)*ppiVar10) >> 0x10) +
                    (int)DAT_803de218[0x540] + (int)DAT_803de218[0x545]);
      }
      else {
        uVar3 = 0;
        uVar8 = 0;
        iVar4 = 0;
        do {
          ppiVar10 = DAT_803de218 + (uVar8 & 0xff) * 0xe + 0x53a;
          if (*ppiVar10 != (int *)0x0) {
            while ((ppiVar9 = (int **)ppiVar10[1], *ppiVar9 != (int *)0xffffffff &&
                   (*ppiVar9 <= ppiVar10[(uint)*(byte *)(ppiVar10 + 0xc) * 2 + 9]))) {
              if ((DAT_803de218[0x46][4] & 0x40000000U) == 0) {
                FUN_8026f53c(ppiVar9[1],DAT_803de220 & 0xff,uVar8 & 0xff);
                ppiVar10[2] = (int *)(ppiVar10[1][1] << 10);
              }
              else {
                piVar2 = ppiVar9[1];
                ppiVar10[2] = piVar2;
                FUN_8026f53c((uint)piVar2 >> 10,DAT_803de220 & 0xff,uVar8 & 0xff);
              }
              ppiVar10[1] = ppiVar10[1] + 2;
            }
          }
          ppiVar10 = DAT_803de218;
          local_78 = (double)CONCAT44(0x43300000,*(undefined4 *)((int)DAT_803de218 + iVar4 + 0x14f0)
                                     );
          dVar16 = (double)((float)(dVar20 * (double)((float)(local_78 - dVar21) *
                                                     (float)((double)CONCAT44(0x43300000,param_1) -
                                                            dVar21))) *
                           (float)(dVar17 * (double)(float)((double)CONCAT44(0x43300000,
                                                                             (uint)*(ushort *)
                                                                                    ((int)
                                                  DAT_803de218 + iVar4 + 0x151a)) - dVar21)));
          dVar15 = (double)(float)(dVar18 * dVar16);
          if (dVar19 <= ABS(dVar15)) {
            FUN_8028660c((double)(float)(dVar15 / dVar18));
            dVar14 = (double)FUN_802864b8();
            dVar15 = (double)(float)(dVar15 - (double)(float)(dVar18 * dVar14));
          }
          uVar6 = FUN_80285fb4(dVar15);
          *(undefined4 *)
           ((int)ppiVar10 +
           (uint)*(byte *)((int)ppiVar10 + iVar4 + 0x1518) * 8 + 0xc + iVar4 + 0x14e8) = uVar6;
          dVar15 = (double)FUN_80294724(dVar16);
          *(int *)((int)ppiVar10 +
                  (uint)*(byte *)((int)ppiVar10 + iVar4 + 0x1518) * 8 + 0x10 + iVar4 + 0x14e8) =
               (int)dVar15;
          uVar7 = FUN_8026e9d0(uVar8 & 0xff,param_1);
          uVar8 = uVar8 + 1;
          uVar3 = uVar3 | uVar7;
          iVar4 = iVar4 + 0x38;
        } while (uVar8 < 0x10);
        iVar4 = FUN_8026c124();
        if (*(char *)((int)DAT_803de218 + 0xee2) == '\0') {
          ppiVar10 = (int **)DAT_803de218[0x39b];
          while (ppiVar9 = ppiVar10, ppiVar9 != (int **)0x0) {
            ppiVar10 = (int **)*ppiVar9;
            if ((ppiVar9[2] != (int *)0xffffffff) && (iVar5 = FUN_8027292c(), iVar5 == -1)) {
              FUN_8026c320(ppiVar9);
            }
          }
        }
        iVar13 = 8;
        uVar8 = *(byte *)((int)DAT_803de218 + 0xee2) + 1;
        *(char *)((int)DAT_803de218 + 0xee2) = (char)uVar8 + (char)(uVar8 / 5) * -5;
        iVar5 = 0;
        do {
          uVar8 = *(int *)((int)DAT_803de218 + iVar5 + 0x1508) +
                  *(int *)((int)DAT_803de218 + iVar5 + 0x14f4);
          *(uint *)((int)DAT_803de218 + iVar5 + 0x1508) = uVar8 & 0xffff;
          *(uint *)((int)DAT_803de218 + iVar5 + 0x150c) =
               (uVar8 >> 0x10) +
               *(int *)((int)DAT_803de218 + iVar5 + 0x14f8) +
               *(int *)((int)DAT_803de218 + iVar5 + 0x150c);
          uVar8 = *(int *)((int)DAT_803de218 + iVar5 + 0x1510) +
                  *(int *)((int)DAT_803de218 + iVar5 + 0x14fc);
          *(uint *)((int)DAT_803de218 + iVar5 + 0x1510) = uVar8 & 0xffff;
          *(uint *)((int)DAT_803de218 + iVar5 + 0x1514) =
               (uVar8 >> 0x10) +
               *(int *)((int)DAT_803de218 + iVar5 + 0x1500) +
               *(int *)((int)DAT_803de218 + iVar5 + 0x1514);
          uVar8 = *(int *)((int)DAT_803de218 + iVar5 + 0x1540) +
                  *(int *)((int)DAT_803de218 + iVar5 + 0x152c);
          *(uint *)((int)DAT_803de218 + iVar5 + 0x1540) = uVar8 & 0xffff;
          *(uint *)((int)DAT_803de218 + iVar5 + 0x1544) =
               (uVar8 >> 0x10) +
               *(int *)((int)DAT_803de218 + iVar5 + 0x1530) +
               *(int *)((int)DAT_803de218 + iVar5 + 0x1544);
          uVar8 = *(int *)((int)DAT_803de218 + iVar5 + 0x1548) +
                  *(int *)((int)DAT_803de218 + iVar5 + 0x1534);
          *(uint *)((int)DAT_803de218 + iVar5 + 0x1548) = uVar8 & 0xffff;
          *(uint *)((int)DAT_803de218 + iVar5 + 0x154c) =
               (uVar8 >> 0x10) +
               *(int *)((int)DAT_803de218 + iVar5 + 0x1538) +
               *(int *)((int)DAT_803de218 + iVar5 + 0x154c);
          iVar13 = iVar13 + -1;
          iVar5 = iVar5 + 0x70;
        } while (iVar13 != 0);
      }
      ppiVar10 = DAT_803de22c;
      if ((uVar3 == 0) && (iVar4 == 0)) {
        ppiVar10 = ppiVar11;
        if ((int **)ppiVar12[1] != (int **)0x0) {
          *ppiVar12[1] = (int)ppiVar11;
          ppiVar10 = DAT_803de234;
        }
        DAT_803de234 = ppiVar10;
        if (ppiVar11 != (int **)0x0) {
          ppiVar11[1] = ppiVar12[1];
        }
        FUN_8026bf54(ppiVar12);
        *(undefined *)(ppiVar12 + 2) = 0;
        ppiVar12[1] = (int *)0x0;
        bVar1 = DAT_803de22c != (int **)0x0;
        *ppiVar12 = (int *)DAT_803de22c;
        ppiVar10 = ppiVar12;
        if (bVar1) {
          DAT_803de22c[1] = (int *)ppiVar12;
        }
      }
    }
  }
  return;
}

