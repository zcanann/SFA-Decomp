// Function: FUN_800a30e8
// Entry: 800a30e8
// Size: 2432 bytes

void FUN_800a30e8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined2 *param_12,
                 int param_13,undefined2 *param_14,uint param_15,int param_16)

{
  bool bVar1;
  float fVar2;
  float fVar3;
  double dVar4;
  double dVar5;
  int iVar6;
  int iVar7;
  int *piVar8;
  int *piVar9;
  int iVar10;
  undefined4 uVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  int iVar15;
  undefined2 *puVar16;
  undefined2 *puVar17;
  uint uVar18;
  uint *puVar19;
  int iVar20;
  int iVar21;
  int iVar22;
  undefined8 extraout_f1;
  undefined8 uVar23;
  
  piVar8 = (int *)FUN_80286828();
  iVar20 = 0;
  iVar13 = 0;
  bVar1 = false;
  piVar9 = &DAT_8039ce58;
  while ((iVar13 < 0x32 && (!bVar1))) {
    if (*piVar9 == 0) {
      bVar1 = true;
    }
    piVar9 = piVar9 + 1;
    iVar13 = iVar13 + 1;
  }
  if (bVar1) {
    iVar13 = iVar13 + -1;
  }
  else {
    iVar13 = -1;
  }
  if (iVar13 != -1) {
    iVar12 = 0;
    iVar15 = (int)*(char *)((int)piVar8 + 0x5d);
    iVar21 = iVar15;
    if (0 < iVar15) {
      do {
        if (((*(uint *)(*piVar8 + iVar12) & 0xf7fff180) == 0) &&
           (iVar6 = (int)*(short *)((uint *)(*piVar8 + iVar12) + 5), iVar6 != 0)) {
          iVar20 = iVar20 + iVar6;
        }
        iVar12 = iVar12 + 0x18;
        iVar21 = iVar21 + -1;
      } while (iVar21 != 0);
    }
    iVar21 = 0;
    if ((piVar8[0x15] & 0x800U) == 0) {
      iVar21 = param_13 * 0x30 + param_11 * 0x30;
    }
    iVar14 = 0;
    iVar12 = param_13;
    puVar17 = param_14;
    uVar18 = param_15;
    iVar6 = param_16;
    uVar23 = extraout_f1;
    iVar10 = FUN_80023d8c(iVar21 + iVar15 * 0x18 + iVar20 * 2 + 0x240,0x15);
    (&DAT_8039ce58)[iVar13] = iVar10;
    iVar10 = (&DAT_8039ce58)[iVar13];
    if (iVar10 == 0) {
      FUN_800a12cc(uVar23,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0);
    }
    else {
      *(int *)(iVar10 + 300) = iVar10 + 0x140;
      iVar10 = *(int *)((&DAT_8039ce58)[iVar13] + 300);
      if ((piVar8[0x15] & 0x800U) == 0) {
        *(int *)((&DAT_8039ce58)[iVar13] + 0x84) = iVar10;
        iVar7 = param_13 * 0x10;
        *(int *)((&DAT_8039ce58)[iVar13] + 0x88) = iVar10 + iVar7;
        iVar10 = iVar10 + iVar7 + iVar7;
        *(int *)((&DAT_8039ce58)[iVar13] + 0x8c) = iVar10;
        iVar10 = iVar10 + iVar7;
        *(int *)((&DAT_8039ce58)[iVar13] + 0x78) = iVar10;
        iVar7 = param_11 * 0x10;
        iVar10 = iVar10 + iVar7;
        *(int *)((&DAT_8039ce58)[iVar13] + 0x7c) = iVar10;
        iVar10 = iVar10 + iVar7;
        *(int *)((&DAT_8039ce58)[iVar13] + 0x80) = iVar10;
        iVar10 = iVar10 + iVar7;
      }
      *(int *)((&DAT_8039ce58)[iVar13] + 0x90) = iVar10;
      *(int *)((&DAT_8039ce58)[iVar13] + 0x94) = iVar10 + 0x80;
      iVar7 = param_13;
      if (piVar8[0x10] != 0) {
        iVar7 = param_13 / piVar8[0x10];
      }
      if ((piVar8[0x15] & 0x800U) == 0) {
        iVar14 = 0;
        iVar10 = 0;
        do {
          puVar17 = *(undefined2 **)((&DAT_8039ce58)[iVar13] + iVar10 + 0x84);
          iVar12 = 0;
          iVar15 = 0;
          puVar16 = param_14;
          iVar22 = param_13;
          if (0 < param_13) {
            do {
              if (((piVar8[0x15] & 0x8000000U) != 0) && (iVar15 == iVar7)) {
                iVar12 = piVar8[0xf];
              }
              *(char *)((int)puVar17 + 1) = (char)*puVar16 - (char)iVar12;
              *(char *)(puVar17 + 1) = (char)puVar16[1] - (char)iVar12;
              uVar18 = (short)puVar16[2] - iVar12 & 0xff;
              *(char *)((int)puVar17 + 3) = (char)((short)puVar16[2] - iVar12);
              puVar16 = puVar16 + 3;
              puVar17 = puVar17 + 8;
              iVar15 = iVar15 + 1;
              iVar22 = iVar22 + -1;
            } while (iVar22 != 0);
          }
          iVar10 = iVar10 + 4;
          iVar14 = iVar14 + 1;
        } while (iVar14 < 3);
      }
      *(undefined4 *)((&DAT_8039ce58)[iVar13] + 0x98) = 0;
      *(undefined *)((&DAT_8039ce58)[iVar13] + 0x13f) = 0;
      if (param_16 == 0) {
        if (param_15 != 0) {
          uVar11 = FUN_80054ed0(uVar23,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                param_15,iVar10,iVar14,iVar15,iVar12,puVar17,uVar18,iVar6);
          *(undefined4 *)((&DAT_8039ce58)[iVar13] + 0x98) = uVar11;
          *(undefined *)((&DAT_8039ce58)[iVar13] + 0x13f) = 0;
        }
      }
      else {
        *(int *)((&DAT_8039ce58)[iVar13] + 0x98) = param_16;
        *(undefined *)((&DAT_8039ce58)[iVar13] + 0x13f) = 1;
      }
      if ((piVar8[0x15] & 0x800U) == 0) {
        iVar15 = 0;
        iVar12 = 0;
        do {
          puVar16 = *(undefined2 **)((&DAT_8039ce58)[iVar13] + iVar12 + 0x78);
          puVar17 = param_12;
          iVar6 = param_11;
          if (0 < param_11) {
            do {
              *puVar16 = *puVar17;
              puVar16[1] = puVar17[1];
              puVar16[2] = puVar17[2];
              fVar2 = FLOAT_803e00e0;
              dVar5 = DOUBLE_803e00c8;
              dVar4 = DOUBLE_803e00c0;
              if (*(int *)((&DAT_8039ce58)[iVar13] + 0x98) != 0) {
                puVar16[4] = (short)(int)(FLOAT_803e00e0 *
                                         ((float)((double)CONCAT44(0x43300000,
                                                                   (int)(short)puVar17[3] ^
                                                                   0x80000000) - DOUBLE_803e00c8) /
                                         (float)((double)CONCAT44(0x43300000,
                                                                  (uint)*(ushort *)
                                                                         (*(int *)((&DAT_8039ce58)
                                                                                   [iVar13] + 0x98)
                                                                         + 10)) - DOUBLE_803e00c0)))
                ;
                puVar16[5] = (short)(int)(fVar2 * ((float)((double)CONCAT44(0x43300000,
                                                                            (int)(short)puVar17[4] ^
                                                                            0x80000000) - dVar5) /
                                                  (float)((double)CONCAT44(0x43300000,
                                                                           (uint)*(ushort *)
                                                                                  (*(int *)((&
                                                  DAT_8039ce58)[iVar13] + 0x98) + 0xc)) - dVar4)));
              }
              *(undefined *)(puVar16 + 6) = 0xff;
              *(undefined *)((int)puVar16 + 0xd) = 0xff;
              *(undefined *)(puVar16 + 7) = 0xff;
              *(undefined *)((int)puVar16 + 0xf) = 0xff;
              puVar16 = puVar16 + 8;
              puVar17 = puVar17 + 5;
              iVar6 = iVar6 + -1;
            } while (iVar6 != 0);
          }
          iVar12 = iVar12 + 4;
          iVar15 = iVar15 + 1;
        } while (iVar15 < 3);
      }
      *(undefined *)((&DAT_8039ce58)[iVar13] + 0x139) = *(undefined *)((int)piVar8 + 0x5d);
      *(undefined4 *)((&DAT_8039ce58)[iVar13] + 0x114) = 0;
      *(undefined4 *)((&DAT_8039ce58)[iVar13] + 0x118) = 0;
      *(undefined4 *)((&DAT_8039ce58)[iVar13] + 0x11c) = 0;
      *(undefined4 *)((&DAT_8039ce58)[iVar13] + 0xa0) = 0;
      *(undefined *)((&DAT_8039ce58)[iVar13] + 0x13a) = 0;
      *(undefined *)((&DAT_8039ce58)[iVar13] + 0x13d) = 0;
      *(undefined2 *)((&DAT_8039ce58)[iVar13] + 0x110) = 0;
      *(undefined2 *)((&DAT_8039ce58)[iVar13] + 0x10e) = 0xffff;
      *(undefined *)((&DAT_8039ce58)[iVar13] + 0x13c) = 0;
      *(undefined2 *)((&DAT_8039ce58)[iVar13] + 0xee) = *(undefined2 *)((int)piVar8 + 0x46);
      *(undefined2 *)((&DAT_8039ce58)[iVar13] + 0xf0) = *(undefined2 *)(piVar8 + 0x12);
      *(undefined2 *)((&DAT_8039ce58)[iVar13] + 0xf2) = *(undefined2 *)((int)piVar8 + 0x4a);
      *(undefined2 *)((&DAT_8039ce58)[iVar13] + 0xf4) = *(undefined2 *)(piVar8 + 0x13);
      *(undefined2 *)((&DAT_8039ce58)[iVar13] + 0xf6) = *(undefined2 *)((int)piVar8 + 0x4e);
      *(undefined2 *)((&DAT_8039ce58)[iVar13] + 0xf8) = *(undefined2 *)(piVar8 + 0x14);
      *(undefined2 *)((&DAT_8039ce58)[iVar13] + 0xfa) = *(undefined2 *)((int)piVar8 + 0x52);
      *(int *)((&DAT_8039ce58)[iVar13] + 0x9c) =
           iVar21 + *(int *)((&DAT_8039ce58)[iVar13] + 300) + 0x100;
      *(undefined4 *)((&DAT_8039ce58)[iVar13] + 8) = 0;
      if (iVar20 != 0) {
        *(int *)((&DAT_8039ce58)[iVar13] + 8) =
             *(int *)((&DAT_8039ce58)[iVar13] + 0x9c) + *(char *)((int)piVar8 + 0x5d) * 0x18;
      }
      iVar12 = *(int *)((&DAT_8039ce58)[iVar13] + 8);
      iVar20 = 0;
      for (iVar21 = 0; iVar15 = (&DAT_8039ce58)[iVar13], iVar21 < *(char *)(iVar15 + 0x139);
          iVar21 = iVar21 + 1) {
        *(undefined *)(*(int *)(iVar15 + 0x9c) + iVar20 + 0x16) =
             *(undefined *)(*piVar8 + iVar20 + 0x16);
        iVar15 = iVar20 + 0x14;
        *(undefined2 *)(*(int *)((&DAT_8039ce58)[iVar13] + 0x9c) + iVar15) =
             *(undefined2 *)(*piVar8 + iVar15);
        iVar6 = 0;
        *(undefined4 *)(*(int *)((&DAT_8039ce58)[iVar13] + 0x9c) + iVar20 + 0x10) = 0;
        *(undefined4 *)(*(int *)((&DAT_8039ce58)[iVar13] + 0x9c) + iVar20) =
             *(undefined4 *)(*piVar8 + iVar20);
        puVar19 = (uint *)(*(int *)((&DAT_8039ce58)[iVar13] + 0x9c) + iVar20);
        if (((*puVar19 & 0xf7fff180) == 0) && (*(short *)(puVar19 + 5) != 0)) {
          puVar19[4] = 0;
          *(int *)(*(int *)((&DAT_8039ce58)[iVar13] + 0x9c) + iVar20 + 0x10) = iVar12;
          iVar12 = iVar12 + *(short *)(*(int *)((&DAT_8039ce58)[iVar13] + 0x9c) + iVar15) * 2;
          iVar15 = 0;
          for (; iVar10 = iVar20 + *(int *)((&DAT_8039ce58)[iVar13] + 0x9c),
              iVar6 < *(short *)(iVar10 + 0x14); iVar6 = iVar6 + 1) {
            *(undefined2 *)(*(int *)(iVar10 + 0x10) + iVar15) =
                 *(undefined2 *)(*(int *)(iVar20 + *piVar8 + 0x10) + iVar15);
            iVar15 = iVar15 + 2;
          }
        }
        *(undefined4 *)(*(int *)((&DAT_8039ce58)[iVar13] + 0x9c) + iVar20 + 4) =
             *(undefined4 *)(*piVar8 + iVar20 + 4);
        *(undefined4 *)(*(int *)((&DAT_8039ce58)[iVar13] + 0x9c) + iVar20 + 8) =
             *(undefined4 *)(*piVar8 + iVar20 + 8);
        *(undefined4 *)(*(int *)((&DAT_8039ce58)[iVar13] + 0x9c) + iVar20 + 0xc) =
             *(undefined4 *)(*piVar8 + iVar20 + 0xc);
        iVar20 = iVar20 + 0x18;
      }
      *(undefined2 *)(iVar15 + 0xfc) = 0xffff;
      iVar20 = (&DAT_8039ce58)[iVar13];
      *(undefined2 *)(iVar20 + 0xfe) =
           *(undefined2 *)(iVar20 + *(short *)(iVar20 + 0xfc) * 2 + 0xee);
      *(int *)((&DAT_8039ce58)[iVar13] + 0xa4) = piVar8[0x15];
      *(int *)((&DAT_8039ce58)[iVar13] + 0x60) = piVar8[0xb];
      *(int *)((&DAT_8039ce58)[iVar13] + 100) = piVar8[0xc];
      *(int *)((&DAT_8039ce58)[iVar13] + 0x68) = piVar8[0xd];
      *(int *)((&DAT_8039ce58)[iVar13] + 0xd4) = piVar8[0xe];
      if ((*(uint *)((&DAT_8039ce58)[iVar13] + 0xa4) & 1) != 0) {
        *(int *)((&DAT_8039ce58)[iVar13] + 0x18) = piVar8[0xb];
        *(int *)((&DAT_8039ce58)[iVar13] + 0x1c) = piVar8[0xc];
        *(int *)((&DAT_8039ce58)[iVar13] + 0x20) = piVar8[0xd];
      }
      fVar2 = FLOAT_803e00b0;
      *(float *)((&DAT_8039ce58)[iVar13] + 0x24) = FLOAT_803e00b0;
      *(float *)((&DAT_8039ce58)[iVar13] + 0x28) = fVar2;
      *(float *)((&DAT_8039ce58)[iVar13] + 0x2c) = fVar2;
      fVar3 = FLOAT_803e00b4;
      *(float *)((&DAT_8039ce58)[iVar13] + 0x30) = FLOAT_803e00b4;
      *(float *)((&DAT_8039ce58)[iVar13] + 0x34) = fVar3;
      *(float *)((&DAT_8039ce58)[iVar13] + 0x38) = fVar3;
      *(float *)((&DAT_8039ce58)[iVar13] + 0x40) = fVar2;
      *(float *)((&DAT_8039ce58)[iVar13] + 0x44) = fVar2;
      *(float *)((&DAT_8039ce58)[iVar13] + 0x3c) = fVar2;
      *(float *)((&DAT_8039ce58)[iVar13] + 0x50) = fVar3;
      *(float *)((&DAT_8039ce58)[iVar13] + 0x48) = fVar3;
      *(float *)((&DAT_8039ce58)[iVar13] + 0x4c) = fVar3;
      *(float *)((&DAT_8039ce58)[iVar13] + 0x5c) = fVar2;
      *(float *)((&DAT_8039ce58)[iVar13] + 0x54) = fVar2;
      *(float *)((&DAT_8039ce58)[iVar13] + 0x58) = fVar2;
      *(undefined2 *)((&DAT_8039ce58)[iVar13] + 0x106) = 0;
      *(undefined2 *)((&DAT_8039ce58)[iVar13] + 0x108) = 0;
      *(undefined2 *)((&DAT_8039ce58)[iVar13] + 0x10a) = 0;
      *(undefined2 *)((&DAT_8039ce58)[iVar13] + 0x120) = 0;
      *(undefined2 *)((&DAT_8039ce58)[iVar13] + 0x122) = 0;
      *(undefined2 *)((&DAT_8039ce58)[iVar13] + 0x124) = 0;
      *(float *)((&DAT_8039ce58)[iVar13] + 0xac) = fVar2;
      *(float *)((&DAT_8039ce58)[iVar13] + 0xb0) = fVar2;
      *(float *)((&DAT_8039ce58)[iVar13] + 0xb4) = fVar2;
      *(float *)((&DAT_8039ce58)[iVar13] + 0xb8) = fVar2;
      *(float *)((&DAT_8039ce58)[iVar13] + 0xbc) = fVar2;
      *(float *)((&DAT_8039ce58)[iVar13] + 0xc0) = fVar2;
      *(float *)((&DAT_8039ce58)[iVar13] + 0xc4) = fVar2;
      *(float *)((&DAT_8039ce58)[iVar13] + 200) = fVar2;
      *(float *)((&DAT_8039ce58)[iVar13] + 0xcc) = fVar2;
      *(float *)((&DAT_8039ce58)[iVar13] + 0xd0) = fVar2;
      *(int *)((&DAT_8039ce58)[iVar13] + 0x6c) = piVar8[8];
      *(int *)((&DAT_8039ce58)[iVar13] + 0x70) = piVar8[9];
      *(int *)((&DAT_8039ce58)[iVar13] + 0x74) = piVar8[10];
      DAT_803ddf00 = DAT_803ddf00 + 1;
      if (20000 < DAT_803ddf00) {
        DAT_803ddf00 = 0;
      }
      *(short *)((&DAT_8039ce58)[iVar13] + 0x10c) = DAT_803ddf00;
      *(undefined *)((&DAT_8039ce58)[iVar13] + 0x126) = DAT_803ddf02;
      *(short *)((&DAT_8039ce58)[iVar13] + 0xea) = (short)param_11;
      *(short *)((&DAT_8039ce58)[iVar13] + 0xec) = (short)param_13;
      *(int *)((&DAT_8039ce58)[iVar13] + 4) = piVar8[1];
      *(undefined4 *)(&DAT_8039ce58)[iVar13] = 0;
      *(undefined *)((&DAT_8039ce58)[iVar13] + 0x135) = *(undefined *)(piVar8 + 0x17);
      *(char *)((&DAT_8039ce58)[iVar13] + 0x136) = (char)piVar8[0x10];
      *(char *)((&DAT_8039ce58)[iVar13] + 0x137) = (char)piVar8[0xf];
      *(undefined *)((&DAT_8039ce58)[iVar13] + 0x138) = *(undefined *)((int)piVar8 + 0x59);
      *(undefined2 *)((&DAT_8039ce58)[iVar13] + 0xe6) = 0;
      *(undefined *)((&DAT_8039ce58)[iVar13] + 0x130) = 0;
      *(undefined *)((&DAT_8039ce58)[iVar13] + 0x13b) = 0;
      *(undefined *)((&DAT_8039ce58)[iVar13] + 0x13e) = 0;
      *(undefined *)((&DAT_8039ce58)[iVar13] + 0x132) = *(undefined *)((int)piVar8 + 0x5b);
      iVar20 = (&DAT_8039ce58)[iVar13];
      if (*(byte *)(iVar20 + 0x132) == 0) {
        *(undefined *)(iVar20 + 0x133) = 0;
      }
      else {
        *(char *)(iVar20 + 0x133) = (char)(0x3c / *(byte *)(iVar20 + 0x132));
      }
      iVar20 = (&DAT_8039ce58)[iVar13];
      if (*(byte *)(iVar20 + 0x133) == 0) {
        *(undefined *)(iVar20 + 0x134) = 0;
      }
      else {
        *(char *)(iVar20 + 0x134) = (char)(0xff / *(byte *)(iVar20 + 0x133));
      }
      *(undefined *)((&DAT_8039ce58)[iVar13] + 0x131) = 0;
      *(int *)((&DAT_8039ce58)[iVar13] + 0xa8) = (int)*(short *)(piVar8 + 0x11);
    }
  }
  FUN_80286874();
  return;
}

