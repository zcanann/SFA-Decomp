// Function: FUN_800a2e5c
// Entry: 800a2e5c
// Size: 2432 bytes

void FUN_800a2e5c(undefined4 param_1,undefined4 param_2,int param_3,undefined2 *param_4,int param_5,
                 undefined2 *param_6,int param_7,int param_8)

{
  char cVar1;
  float fVar2;
  float fVar3;
  double dVar4;
  double dVar5;
  int iVar6;
  int *piVar7;
  int *piVar8;
  undefined4 uVar9;
  undefined2 *puVar10;
  bool bVar12;
  int iVar11;
  int iVar13;
  int iVar14;
  int iVar15;
  undefined2 *puVar16;
  int iVar17;
  int iVar18;
  uint *puVar19;
  int iVar20;
  int iVar21;
  int iVar22;
  
  piVar7 = (int *)FUN_802860c4();
  iVar20 = 0;
  iVar13 = 0;
  bVar12 = false;
  piVar8 = &DAT_8039c1f8;
  while ((iVar13 < 0x32 && (!bVar12))) {
    if (*piVar8 == 0) {
      bVar12 = true;
    }
    piVar8 = piVar8 + 1;
    iVar13 = iVar13 + 1;
  }
  if (bVar12) {
    iVar13 = iVar13 + -1;
  }
  else {
    iVar13 = -1;
  }
  if (iVar13 == -1) {
    iVar13 = 0;
  }
  else {
    iVar11 = 0;
    iVar14 = (int)*(char *)((int)piVar7 + 0x5d);
    iVar21 = iVar14;
    if (0 < iVar14) {
      do {
        if (((*(uint *)(*piVar7 + iVar11) & 0xf7fff180) == 0) &&
           (iVar6 = (int)*(short *)((uint *)(*piVar7 + iVar11) + 5), iVar6 != 0)) {
          iVar20 = iVar20 + iVar6;
        }
        iVar11 = iVar11 + 0x18;
        iVar21 = iVar21 + -1;
      } while (iVar21 != 0);
    }
    iVar21 = 0;
    if ((piVar7[0x15] & 0x800U) == 0) {
      iVar21 = param_5 * 0x30 + param_3 * 0x30;
    }
    uVar9 = FUN_80023cc8(iVar21 + iVar14 * 0x18 + iVar20 * 2 + 0x240,0x15,0);
    (&DAT_8039c1f8)[iVar13] = uVar9;
    iVar11 = (&DAT_8039c1f8)[iVar13];
    if (iVar11 == 0) {
      FUN_800a1040(0,0);
      iVar13 = -1;
    }
    else {
      *(int *)(iVar11 + 300) = iVar11 + 0x140;
      iVar11 = *(int *)((&DAT_8039c1f8)[iVar13] + 300);
      if ((piVar7[0x15] & 0x800U) == 0) {
        *(int *)((&DAT_8039c1f8)[iVar13] + 0x84) = iVar11;
        iVar14 = param_5 * 0x10;
        *(int *)((&DAT_8039c1f8)[iVar13] + 0x88) = iVar11 + iVar14;
        iVar11 = iVar11 + iVar14 + iVar14;
        *(int *)((&DAT_8039c1f8)[iVar13] + 0x8c) = iVar11;
        iVar11 = iVar11 + iVar14;
        *(int *)((&DAT_8039c1f8)[iVar13] + 0x78) = iVar11;
        iVar14 = param_3 * 0x10;
        iVar11 = iVar11 + iVar14;
        *(int *)((&DAT_8039c1f8)[iVar13] + 0x7c) = iVar11;
        iVar11 = iVar11 + iVar14;
        *(int *)((&DAT_8039c1f8)[iVar13] + 0x80) = iVar11;
        iVar11 = iVar11 + iVar14;
      }
      *(int *)((&DAT_8039c1f8)[iVar13] + 0x90) = iVar11;
      *(int *)((&DAT_8039c1f8)[iVar13] + 0x94) = iVar11 + 0x80;
      iVar11 = param_5;
      if (piVar7[0x10] != 0) {
        iVar11 = param_5 / piVar7[0x10];
      }
      if ((piVar7[0x15] & 0x800U) == 0) {
        iVar6 = 0;
        iVar14 = 0;
        do {
          iVar18 = *(int *)((&DAT_8039c1f8)[iVar13] + iVar14 + 0x84);
          iVar17 = 0;
          iVar15 = 0;
          puVar10 = param_6;
          iVar22 = param_5;
          if (0 < param_5) {
            do {
              if (((piVar7[0x15] & 0x8000000U) != 0) && (iVar15 == iVar11)) {
                iVar17 = piVar7[0xf];
              }
              cVar1 = (char)iVar17;
              *(char *)(iVar18 + 1) = (char)*puVar10 - cVar1;
              *(char *)(iVar18 + 2) = (char)puVar10[1] - cVar1;
              *(char *)(iVar18 + 3) = (char)puVar10[2] - cVar1;
              puVar10 = puVar10 + 3;
              iVar18 = iVar18 + 0x10;
              iVar15 = iVar15 + 1;
              iVar22 = iVar22 + -1;
            } while (iVar22 != 0);
          }
          iVar14 = iVar14 + 4;
          iVar6 = iVar6 + 1;
        } while (iVar6 < 3);
      }
      *(undefined4 *)((&DAT_8039c1f8)[iVar13] + 0x98) = 0;
      *(undefined *)((&DAT_8039c1f8)[iVar13] + 0x13f) = 0;
      if (param_8 == 0) {
        if (param_7 != 0) {
          uVar9 = FUN_80054d54(param_7);
          *(undefined4 *)((&DAT_8039c1f8)[iVar13] + 0x98) = uVar9;
          *(undefined *)((&DAT_8039c1f8)[iVar13] + 0x13f) = 0;
        }
      }
      else {
        *(int *)((&DAT_8039c1f8)[iVar13] + 0x98) = param_8;
        *(undefined *)((&DAT_8039c1f8)[iVar13] + 0x13f) = 1;
      }
      if ((piVar7[0x15] & 0x800U) == 0) {
        iVar14 = 0;
        iVar11 = 0;
        do {
          puVar16 = *(undefined2 **)((&DAT_8039c1f8)[iVar13] + iVar11 + 0x78);
          puVar10 = param_4;
          iVar6 = param_3;
          if (0 < param_3) {
            do {
              *puVar16 = *puVar10;
              puVar16[1] = puVar10[1];
              puVar16[2] = puVar10[2];
              fVar2 = FLOAT_803df460;
              dVar5 = DOUBLE_803df448;
              dVar4 = DOUBLE_803df440;
              if (*(int *)((&DAT_8039c1f8)[iVar13] + 0x98) != 0) {
                puVar16[4] = (short)(int)(FLOAT_803df460 *
                                         ((float)((double)CONCAT44(0x43300000,
                                                                   (int)(short)puVar10[3] ^
                                                                   0x80000000) - DOUBLE_803df448) /
                                         (float)((double)CONCAT44(0x43300000,
                                                                  (uint)*(ushort *)
                                                                         (*(int *)((&DAT_8039c1f8)
                                                                                   [iVar13] + 0x98)
                                                                         + 10)) - DOUBLE_803df440)))
                ;
                puVar16[5] = (short)(int)(fVar2 * ((float)((double)CONCAT44(0x43300000,
                                                                            (int)(short)puVar10[4] ^
                                                                            0x80000000) - dVar5) /
                                                  (float)((double)CONCAT44(0x43300000,
                                                                           (uint)*(ushort *)
                                                                                  (*(int *)((&
                                                  DAT_8039c1f8)[iVar13] + 0x98) + 0xc)) - dVar4)));
              }
              *(undefined *)(puVar16 + 6) = 0xff;
              *(undefined *)((int)puVar16 + 0xd) = 0xff;
              *(undefined *)(puVar16 + 7) = 0xff;
              *(undefined *)((int)puVar16 + 0xf) = 0xff;
              puVar16 = puVar16 + 8;
              puVar10 = puVar10 + 5;
              iVar6 = iVar6 + -1;
            } while (iVar6 != 0);
          }
          iVar11 = iVar11 + 4;
          iVar14 = iVar14 + 1;
        } while (iVar14 < 3);
      }
      *(undefined *)((&DAT_8039c1f8)[iVar13] + 0x139) = *(undefined *)((int)piVar7 + 0x5d);
      *(undefined4 *)((&DAT_8039c1f8)[iVar13] + 0x114) = 0;
      *(undefined4 *)((&DAT_8039c1f8)[iVar13] + 0x118) = 0;
      *(undefined4 *)((&DAT_8039c1f8)[iVar13] + 0x11c) = 0;
      *(undefined4 *)((&DAT_8039c1f8)[iVar13] + 0xa0) = 0;
      *(undefined *)((&DAT_8039c1f8)[iVar13] + 0x13a) = 0;
      *(undefined *)((&DAT_8039c1f8)[iVar13] + 0x13d) = 0;
      *(undefined2 *)((&DAT_8039c1f8)[iVar13] + 0x110) = 0;
      *(undefined2 *)((&DAT_8039c1f8)[iVar13] + 0x10e) = 0xffff;
      *(undefined *)((&DAT_8039c1f8)[iVar13] + 0x13c) = 0;
      *(undefined2 *)((&DAT_8039c1f8)[iVar13] + 0xee) = *(undefined2 *)((int)piVar7 + 0x46);
      *(undefined2 *)((&DAT_8039c1f8)[iVar13] + 0xf0) = *(undefined2 *)(piVar7 + 0x12);
      *(undefined2 *)((&DAT_8039c1f8)[iVar13] + 0xf2) = *(undefined2 *)((int)piVar7 + 0x4a);
      *(undefined2 *)((&DAT_8039c1f8)[iVar13] + 0xf4) = *(undefined2 *)(piVar7 + 0x13);
      *(undefined2 *)((&DAT_8039c1f8)[iVar13] + 0xf6) = *(undefined2 *)((int)piVar7 + 0x4e);
      *(undefined2 *)((&DAT_8039c1f8)[iVar13] + 0xf8) = *(undefined2 *)(piVar7 + 0x14);
      *(undefined2 *)((&DAT_8039c1f8)[iVar13] + 0xfa) = *(undefined2 *)((int)piVar7 + 0x52);
      *(int *)((&DAT_8039c1f8)[iVar13] + 0x9c) =
           iVar21 + *(int *)((&DAT_8039c1f8)[iVar13] + 300) + 0x100;
      *(undefined4 *)((&DAT_8039c1f8)[iVar13] + 8) = 0;
      if (iVar20 != 0) {
        *(int *)((&DAT_8039c1f8)[iVar13] + 8) =
             *(int *)((&DAT_8039c1f8)[iVar13] + 0x9c) + *(char *)((int)piVar7 + 0x5d) * 0x18;
      }
      iVar11 = *(int *)((&DAT_8039c1f8)[iVar13] + 8);
      iVar20 = 0;
      for (iVar21 = 0; iVar14 = (&DAT_8039c1f8)[iVar13], iVar21 < *(char *)(iVar14 + 0x139);
          iVar21 = iVar21 + 1) {
        *(undefined *)(*(int *)(iVar14 + 0x9c) + iVar20 + 0x16) =
             *(undefined *)(*piVar7 + iVar20 + 0x16);
        iVar14 = iVar20 + 0x14;
        *(undefined2 *)(*(int *)((&DAT_8039c1f8)[iVar13] + 0x9c) + iVar14) =
             *(undefined2 *)(*piVar7 + iVar14);
        iVar6 = 0;
        *(undefined4 *)(*(int *)((&DAT_8039c1f8)[iVar13] + 0x9c) + iVar20 + 0x10) = 0;
        *(undefined4 *)(*(int *)((&DAT_8039c1f8)[iVar13] + 0x9c) + iVar20) =
             *(undefined4 *)(*piVar7 + iVar20);
        puVar19 = (uint *)(*(int *)((&DAT_8039c1f8)[iVar13] + 0x9c) + iVar20);
        if (((*puVar19 & 0xf7fff180) == 0) && (*(short *)(puVar19 + 5) != 0)) {
          puVar19[4] = 0;
          *(int *)(*(int *)((&DAT_8039c1f8)[iVar13] + 0x9c) + iVar20 + 0x10) = iVar11;
          iVar11 = iVar11 + *(short *)(*(int *)((&DAT_8039c1f8)[iVar13] + 0x9c) + iVar14) * 2;
          iVar14 = 0;
          for (; iVar22 = iVar20 + *(int *)((&DAT_8039c1f8)[iVar13] + 0x9c),
              iVar6 < *(short *)(iVar22 + 0x14); iVar6 = iVar6 + 1) {
            *(undefined2 *)(*(int *)(iVar22 + 0x10) + iVar14) =
                 *(undefined2 *)(*(int *)(iVar20 + *piVar7 + 0x10) + iVar14);
            iVar14 = iVar14 + 2;
          }
        }
        *(undefined4 *)(*(int *)((&DAT_8039c1f8)[iVar13] + 0x9c) + iVar20 + 4) =
             *(undefined4 *)(*piVar7 + iVar20 + 4);
        *(undefined4 *)(*(int *)((&DAT_8039c1f8)[iVar13] + 0x9c) + iVar20 + 8) =
             *(undefined4 *)(*piVar7 + iVar20 + 8);
        *(undefined4 *)(*(int *)((&DAT_8039c1f8)[iVar13] + 0x9c) + iVar20 + 0xc) =
             *(undefined4 *)(*piVar7 + iVar20 + 0xc);
        iVar20 = iVar20 + 0x18;
      }
      *(undefined2 *)(iVar14 + 0xfc) = 0xffff;
      iVar20 = (&DAT_8039c1f8)[iVar13];
      *(undefined2 *)(iVar20 + 0xfe) =
           *(undefined2 *)(iVar20 + *(short *)(iVar20 + 0xfc) * 2 + 0xee);
      *(int *)((&DAT_8039c1f8)[iVar13] + 0xa4) = piVar7[0x15];
      *(int *)((&DAT_8039c1f8)[iVar13] + 0x60) = piVar7[0xb];
      *(int *)((&DAT_8039c1f8)[iVar13] + 100) = piVar7[0xc];
      *(int *)((&DAT_8039c1f8)[iVar13] + 0x68) = piVar7[0xd];
      *(int *)((&DAT_8039c1f8)[iVar13] + 0xd4) = piVar7[0xe];
      if ((*(uint *)((&DAT_8039c1f8)[iVar13] + 0xa4) & 1) != 0) {
        *(int *)((&DAT_8039c1f8)[iVar13] + 0x18) = piVar7[0xb];
        *(int *)((&DAT_8039c1f8)[iVar13] + 0x1c) = piVar7[0xc];
        *(int *)((&DAT_8039c1f8)[iVar13] + 0x20) = piVar7[0xd];
      }
      fVar2 = FLOAT_803df430;
      *(float *)((&DAT_8039c1f8)[iVar13] + 0x24) = FLOAT_803df430;
      *(float *)((&DAT_8039c1f8)[iVar13] + 0x28) = fVar2;
      *(float *)((&DAT_8039c1f8)[iVar13] + 0x2c) = fVar2;
      fVar3 = FLOAT_803df434;
      *(float *)((&DAT_8039c1f8)[iVar13] + 0x30) = FLOAT_803df434;
      *(float *)((&DAT_8039c1f8)[iVar13] + 0x34) = fVar3;
      *(float *)((&DAT_8039c1f8)[iVar13] + 0x38) = fVar3;
      *(float *)((&DAT_8039c1f8)[iVar13] + 0x40) = fVar2;
      *(float *)((&DAT_8039c1f8)[iVar13] + 0x44) = fVar2;
      *(float *)((&DAT_8039c1f8)[iVar13] + 0x3c) = fVar2;
      *(float *)((&DAT_8039c1f8)[iVar13] + 0x50) = fVar3;
      *(float *)((&DAT_8039c1f8)[iVar13] + 0x48) = fVar3;
      *(float *)((&DAT_8039c1f8)[iVar13] + 0x4c) = fVar3;
      *(float *)((&DAT_8039c1f8)[iVar13] + 0x5c) = fVar2;
      *(float *)((&DAT_8039c1f8)[iVar13] + 0x54) = fVar2;
      *(float *)((&DAT_8039c1f8)[iVar13] + 0x58) = fVar2;
      *(undefined2 *)((&DAT_8039c1f8)[iVar13] + 0x106) = 0;
      *(undefined2 *)((&DAT_8039c1f8)[iVar13] + 0x108) = 0;
      *(undefined2 *)((&DAT_8039c1f8)[iVar13] + 0x10a) = 0;
      *(undefined2 *)((&DAT_8039c1f8)[iVar13] + 0x120) = 0;
      *(undefined2 *)((&DAT_8039c1f8)[iVar13] + 0x122) = 0;
      *(undefined2 *)((&DAT_8039c1f8)[iVar13] + 0x124) = 0;
      *(float *)((&DAT_8039c1f8)[iVar13] + 0xac) = fVar2;
      *(float *)((&DAT_8039c1f8)[iVar13] + 0xb0) = fVar2;
      *(float *)((&DAT_8039c1f8)[iVar13] + 0xb4) = fVar2;
      *(float *)((&DAT_8039c1f8)[iVar13] + 0xb8) = fVar2;
      *(float *)((&DAT_8039c1f8)[iVar13] + 0xbc) = fVar2;
      *(float *)((&DAT_8039c1f8)[iVar13] + 0xc0) = fVar2;
      *(float *)((&DAT_8039c1f8)[iVar13] + 0xc4) = fVar2;
      *(float *)((&DAT_8039c1f8)[iVar13] + 200) = fVar2;
      *(float *)((&DAT_8039c1f8)[iVar13] + 0xcc) = fVar2;
      *(float *)((&DAT_8039c1f8)[iVar13] + 0xd0) = fVar2;
      *(int *)((&DAT_8039c1f8)[iVar13] + 0x6c) = piVar7[8];
      *(int *)((&DAT_8039c1f8)[iVar13] + 0x70) = piVar7[9];
      *(int *)((&DAT_8039c1f8)[iVar13] + 0x74) = piVar7[10];
      DAT_803dd280 = DAT_803dd280 + 1;
      if (20000 < DAT_803dd280) {
        DAT_803dd280 = 0;
      }
      *(short *)((&DAT_8039c1f8)[iVar13] + 0x10c) = DAT_803dd280;
      *(undefined *)((&DAT_8039c1f8)[iVar13] + 0x126) = DAT_803dd282;
      *(short *)((&DAT_8039c1f8)[iVar13] + 0xea) = (short)param_3;
      *(short *)((&DAT_8039c1f8)[iVar13] + 0xec) = (short)param_5;
      *(int *)((&DAT_8039c1f8)[iVar13] + 4) = piVar7[1];
      *(undefined4 *)(&DAT_8039c1f8)[iVar13] = 0;
      *(undefined *)((&DAT_8039c1f8)[iVar13] + 0x135) = *(undefined *)(piVar7 + 0x17);
      *(char *)((&DAT_8039c1f8)[iVar13] + 0x136) = (char)piVar7[0x10];
      *(char *)((&DAT_8039c1f8)[iVar13] + 0x137) = (char)piVar7[0xf];
      *(undefined *)((&DAT_8039c1f8)[iVar13] + 0x138) = *(undefined *)((int)piVar7 + 0x59);
      *(undefined2 *)((&DAT_8039c1f8)[iVar13] + 0xe6) = 0;
      *(undefined *)((&DAT_8039c1f8)[iVar13] + 0x130) = 0;
      *(undefined *)((&DAT_8039c1f8)[iVar13] + 0x13b) = 0;
      *(undefined *)((&DAT_8039c1f8)[iVar13] + 0x13e) = 0;
      *(undefined *)((&DAT_8039c1f8)[iVar13] + 0x132) = *(undefined *)((int)piVar7 + 0x5b);
      iVar20 = (&DAT_8039c1f8)[iVar13];
      if (*(byte *)(iVar20 + 0x132) == 0) {
        *(undefined *)(iVar20 + 0x133) = 0;
      }
      else {
        *(char *)(iVar20 + 0x133) = (char)(0x3c / *(byte *)(iVar20 + 0x132));
      }
      iVar20 = (&DAT_8039c1f8)[iVar13];
      if (*(byte *)(iVar20 + 0x133) == 0) {
        *(undefined *)(iVar20 + 0x134) = 0;
      }
      else {
        *(char *)(iVar20 + 0x134) = (char)(0xff / *(byte *)(iVar20 + 0x133));
      }
      *(undefined *)((&DAT_8039c1f8)[iVar13] + 0x131) = 0;
      *(int *)((&DAT_8039c1f8)[iVar13] + 0xa8) = (int)*(short *)(piVar7 + 0x11);
      iVar13 = (int)*(short *)((&DAT_8039c1f8)[iVar13] + 0x10c);
    }
  }
  FUN_80286110(iVar13);
  return;
}

