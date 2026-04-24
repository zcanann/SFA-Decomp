// Function: FUN_8008d088
// Entry: 8008d088
// Size: 2172 bytes

void FUN_8008d088(int param_1)

{
  ushort uVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  
  fVar2 = FLOAT_803df114;
  iVar4 = (&DAT_803dd184)[param_1];
  if (FLOAT_803df114 <= *(float *)(iVar4 + 0x304)) {
    *(ushort *)(iVar4 + 4) = *(ushort *)(iVar4 + 4) & 0xfeff;
    fVar3 = FLOAT_803df108;
    *(float *)((&DAT_803dd184)[param_1] + 0x308) = FLOAT_803df108;
    *(float *)((&DAT_803dd184)[param_1] + 0x304) = fVar3;
    *(float *)((&DAT_803dd184)[param_1] + 0x30c) = fVar2;
    iVar4 = (&DAT_803dd184)[param_1];
    if ((*(char *)(iVar4 + 0x316) != '\0') && ((*(ushort *)(iVar4 + 6) & 0x40) == 0)) {
      *(undefined *)(iVar4 + 0x316) = 0;
    }
    iVar6 = 0;
    iVar4 = 0;
    iVar7 = 2;
    do {
      *(undefined4 *)((&DAT_803dd184)[param_1] + iVar4 + 0x70) =
           *(undefined4 *)((&DAT_803dd184)[param_1] + iVar4 + 0xf4);
      *(undefined4 *)((&DAT_803dd184)[param_1] + iVar4 + 0x74) =
           *(undefined4 *)((&DAT_803dd184)[param_1] + iVar4 + 0xf8);
      *(undefined4 *)((&DAT_803dd184)[param_1] + iVar4 + 0x78) =
           *(undefined4 *)((&DAT_803dd184)[param_1] + iVar4 + 0xfc);
      *(undefined4 *)((&DAT_803dd184)[param_1] + iVar4 + 0x7c) =
           *(undefined4 *)((&DAT_803dd184)[param_1] + iVar4 + 0x100);
      *(undefined4 *)((&DAT_803dd184)[param_1] + iVar4 + 0x80) =
           *(undefined4 *)((&DAT_803dd184)[param_1] + iVar4 + 0x104);
      *(undefined4 *)((&DAT_803dd184)[param_1] + iVar4 + 0x84) =
           *(undefined4 *)((&DAT_803dd184)[param_1] + iVar4 + 0x108);
      *(undefined4 *)((&DAT_803dd184)[param_1] + iVar4 + 0x88) =
           *(undefined4 *)((&DAT_803dd184)[param_1] + iVar4 + 0x10c);
      *(undefined4 *)((&DAT_803dd184)[param_1] + iVar4 + 0x8c) =
           *(undefined4 *)((&DAT_803dd184)[param_1] + iVar4 + 0x110);
      iVar5 = iVar4 + 0x20;
      *(undefined4 *)((&DAT_803dd184)[param_1] + iVar5 + 0x70) =
           *(undefined4 *)((&DAT_803dd184)[param_1] + iVar5 + 0xf4);
      *(undefined4 *)((&DAT_803dd184)[param_1] + iVar5 + 0x74) =
           *(undefined4 *)((&DAT_803dd184)[param_1] + iVar5 + 0xf8);
      *(undefined4 *)((&DAT_803dd184)[param_1] + iVar5 + 0x78) =
           *(undefined4 *)((&DAT_803dd184)[param_1] + iVar5 + 0xfc);
      *(undefined4 *)((&DAT_803dd184)[param_1] + iVar5 + 0x7c) =
           *(undefined4 *)((&DAT_803dd184)[param_1] + iVar5 + 0x100);
      *(undefined4 *)((&DAT_803dd184)[param_1] + iVar5 + 0x80) =
           *(undefined4 *)((&DAT_803dd184)[param_1] + iVar5 + 0x104);
      *(undefined4 *)((&DAT_803dd184)[param_1] + iVar5 + 0x84) =
           *(undefined4 *)((&DAT_803dd184)[param_1] + iVar5 + 0x108);
      *(undefined4 *)((&DAT_803dd184)[param_1] + iVar5 + 0x88) =
           *(undefined4 *)((&DAT_803dd184)[param_1] + iVar5 + 0x10c);
      *(undefined4 *)((&DAT_803dd184)[param_1] + iVar5 + 0x8c) =
           *(undefined4 *)((&DAT_803dd184)[param_1] + iVar5 + 0x110);
      iVar4 = iVar4 + 0x40;
      iVar6 = iVar6 + 0x10;
      iVar7 = iVar7 + -1;
    } while (iVar7 != 0);
    iVar4 = iVar6 * 4;
    iVar7 = 0x21 - iVar6;
    if (iVar6 < 0x21) {
      do {
        *(undefined4 *)((&DAT_803dd184)[param_1] + iVar4 + 0x70) =
             *(undefined4 *)((&DAT_803dd184)[param_1] + iVar4 + 0xf4);
        iVar4 = iVar4 + 4;
        iVar7 = iVar7 + -1;
      } while (iVar7 != 0);
    }
    iVar6 = 0;
    iVar4 = 0;
    iVar7 = 3;
    do {
      *(undefined4 *)((&DAT_803dd184)[param_1] + iVar4 + 0x1fc) =
           *(undefined4 *)((&DAT_803dd184)[param_1] + iVar4 + 0x254);
      *(undefined4 *)((&DAT_803dd184)[param_1] + iVar4 + 0x200) =
           *(undefined4 *)((&DAT_803dd184)[param_1] + iVar4 + 600);
      *(undefined4 *)((&DAT_803dd184)[param_1] + iVar4 + 0x204) =
           *(undefined4 *)((&DAT_803dd184)[param_1] + iVar4 + 0x25c);
      *(undefined4 *)((&DAT_803dd184)[param_1] + iVar4 + 0x208) =
           *(undefined4 *)((&DAT_803dd184)[param_1] + iVar4 + 0x260);
      *(undefined4 *)((&DAT_803dd184)[param_1] + iVar4 + 0x20c) =
           *(undefined4 *)((&DAT_803dd184)[param_1] + iVar4 + 0x264);
      *(undefined4 *)((&DAT_803dd184)[param_1] + iVar4 + 0x210) =
           *(undefined4 *)((&DAT_803dd184)[param_1] + iVar4 + 0x268);
      *(undefined4 *)((&DAT_803dd184)[param_1] + iVar4 + 0x214) =
           *(undefined4 *)((&DAT_803dd184)[param_1] + iVar4 + 0x26c);
      iVar4 = iVar4 + 0x1c;
      iVar6 = iVar6 + 7;
      iVar7 = iVar7 + -1;
    } while (iVar7 != 0);
    iVar4 = iVar6 * 4;
    iVar7 = 0x16 - iVar6;
    if (iVar6 < 0x16) {
      do {
        *(undefined4 *)((&DAT_803dd184)[param_1] + iVar4 + 0x1fc) =
             *(undefined4 *)((&DAT_803dd184)[param_1] + iVar4 + 0x254);
        iVar4 = iVar4 + 4;
        iVar7 = iVar7 + -1;
      } while (iVar7 != 0);
    }
  }
  else {
    if (*(char *)(iVar4 + 0x315) != '\0') {
      fVar2 = FLOAT_803df11c *
              ((float)((double)CONCAT44(0x43300000,*(uint *)(iVar4 + 0x3c) ^ 0x80000000) -
                      DOUBLE_803df130) / FLOAT_803df120);
      if (FLOAT_803df108 == fVar2) {
        fVar2 = FLOAT_803df114;
      }
      *(float *)(iVar4 + 0x308) = FLOAT_803df114 / fVar2;
      iVar6 = 0;
      iVar4 = 0;
      iVar7 = 4;
      do {
        iVar5 = (&DAT_803dd184)[param_1] + iVar4;
        *(float *)(iVar5 + 0x178) = (*(float *)(iVar5 + 0xf4) - *(float *)(iVar5 + 0x70)) / fVar2;
        iVar5 = (&DAT_803dd184)[param_1] + iVar4;
        *(float *)(iVar5 + 0x17c) = (*(float *)(iVar5 + 0xf8) - *(float *)(iVar5 + 0x74)) / fVar2;
        iVar5 = (&DAT_803dd184)[param_1] + iVar4;
        *(float *)(iVar5 + 0x180) = (*(float *)(iVar5 + 0xfc) - *(float *)(iVar5 + 0x78)) / fVar2;
        iVar5 = (&DAT_803dd184)[param_1] + iVar4;
        *(float *)(iVar5 + 0x184) = (*(float *)(iVar5 + 0x100) - *(float *)(iVar5 + 0x7c)) / fVar2;
        iVar5 = (&DAT_803dd184)[param_1] + iVar4;
        *(float *)(iVar5 + 0x188) = (*(float *)(iVar5 + 0x104) - *(float *)(iVar5 + 0x80)) / fVar2;
        iVar5 = (&DAT_803dd184)[param_1] + iVar4;
        *(float *)(iVar5 + 0x18c) = (*(float *)(iVar5 + 0x108) - *(float *)(iVar5 + 0x84)) / fVar2;
        iVar5 = (&DAT_803dd184)[param_1] + iVar4;
        *(float *)(iVar5 + 400) = (*(float *)(iVar5 + 0x10c) - *(float *)(iVar5 + 0x88)) / fVar2;
        iVar5 = (&DAT_803dd184)[param_1] + iVar4;
        *(float *)(iVar5 + 0x194) = (*(float *)(iVar5 + 0x110) - *(float *)(iVar5 + 0x8c)) / fVar2;
        iVar4 = iVar4 + 0x20;
        iVar6 = iVar6 + 8;
        iVar7 = iVar7 + -1;
      } while (iVar7 != 0);
      iVar4 = iVar6 * 4;
      iVar7 = 0x21 - iVar6;
      if (iVar6 < 0x21) {
        do {
          iVar6 = (&DAT_803dd184)[param_1] + iVar4;
          *(float *)(iVar6 + 0x178) = (*(float *)(iVar6 + 0xf4) - *(float *)(iVar6 + 0x70)) / fVar2;
          iVar4 = iVar4 + 4;
          iVar7 = iVar7 + -1;
        } while (iVar7 != 0);
      }
      iVar6 = 0;
      iVar4 = 0;
      iVar7 = 3;
      do {
        iVar5 = (&DAT_803dd184)[param_1] + iVar4;
        *(float *)(iVar5 + 0x2ac) = (*(float *)(iVar5 + 0x254) - *(float *)(iVar5 + 0x1fc)) / fVar2;
        iVar5 = (&DAT_803dd184)[param_1] + iVar4;
        *(float *)(iVar5 + 0x2b0) = (*(float *)(iVar5 + 600) - *(float *)(iVar5 + 0x200)) / fVar2;
        iVar5 = (&DAT_803dd184)[param_1] + iVar4;
        *(float *)(iVar5 + 0x2b4) = (*(float *)(iVar5 + 0x25c) - *(float *)(iVar5 + 0x204)) / fVar2;
        iVar5 = (&DAT_803dd184)[param_1] + iVar4;
        *(float *)(iVar5 + 0x2b8) = (*(float *)(iVar5 + 0x260) - *(float *)(iVar5 + 0x208)) / fVar2;
        iVar5 = (&DAT_803dd184)[param_1] + iVar4;
        *(float *)(iVar5 + 700) = (*(float *)(iVar5 + 0x264) - *(float *)(iVar5 + 0x20c)) / fVar2;
        iVar5 = (&DAT_803dd184)[param_1] + iVar4;
        *(float *)(iVar5 + 0x2c0) = (*(float *)(iVar5 + 0x268) - *(float *)(iVar5 + 0x210)) / fVar2;
        iVar5 = (&DAT_803dd184)[param_1] + iVar4;
        *(float *)(iVar5 + 0x2c4) = (*(float *)(iVar5 + 0x26c) - *(float *)(iVar5 + 0x214)) / fVar2;
        iVar4 = iVar4 + 0x1c;
        iVar6 = iVar6 + 7;
        iVar7 = iVar7 + -1;
      } while (iVar7 != 0);
      iVar4 = iVar6 * 4;
      iVar7 = 0x16 - iVar6;
      if (iVar6 < 0x16) {
        do {
          iVar6 = (&DAT_803dd184)[param_1] + iVar4;
          *(float *)(iVar6 + 0x2ac) =
               (*(float *)(iVar6 + 0x254) - *(float *)(iVar6 + 0x1fc)) / fVar2;
          iVar4 = iVar4 + 4;
          iVar7 = iVar7 + -1;
        } while (iVar7 != 0);
      }
      *(undefined *)((&DAT_803dd184)[param_1] + 0x315) = 0;
    }
    iVar6 = 0;
    iVar4 = 0;
    iVar7 = 4;
    do {
      iVar5 = (&DAT_803dd184)[param_1] + iVar4;
      *(float *)(iVar5 + 0x70) =
           FLOAT_803db414 * *(float *)(iVar5 + 0x178) + *(float *)(iVar5 + 0x70);
      iVar5 = (&DAT_803dd184)[param_1] + iVar4;
      *(float *)(iVar5 + 0x74) =
           FLOAT_803db414 * *(float *)(iVar5 + 0x17c) + *(float *)(iVar5 + 0x74);
      iVar5 = (&DAT_803dd184)[param_1] + iVar4;
      *(float *)(iVar5 + 0x78) =
           FLOAT_803db414 * *(float *)(iVar5 + 0x180) + *(float *)(iVar5 + 0x78);
      iVar5 = (&DAT_803dd184)[param_1] + iVar4;
      *(float *)(iVar5 + 0x7c) =
           FLOAT_803db414 * *(float *)(iVar5 + 0x184) + *(float *)(iVar5 + 0x7c);
      iVar5 = (&DAT_803dd184)[param_1] + iVar4;
      *(float *)(iVar5 + 0x80) =
           FLOAT_803db414 * *(float *)(iVar5 + 0x188) + *(float *)(iVar5 + 0x80);
      iVar5 = (&DAT_803dd184)[param_1] + iVar4;
      *(float *)(iVar5 + 0x84) =
           FLOAT_803db414 * *(float *)(iVar5 + 0x18c) + *(float *)(iVar5 + 0x84);
      iVar5 = (&DAT_803dd184)[param_1] + iVar4;
      *(float *)(iVar5 + 0x88) = FLOAT_803db414 * *(float *)(iVar5 + 400) + *(float *)(iVar5 + 0x88)
      ;
      iVar5 = (&DAT_803dd184)[param_1] + iVar4;
      *(float *)(iVar5 + 0x8c) =
           FLOAT_803db414 * *(float *)(iVar5 + 0x194) + *(float *)(iVar5 + 0x8c);
      iVar4 = iVar4 + 0x20;
      iVar6 = iVar6 + 8;
      iVar7 = iVar7 + -1;
    } while (iVar7 != 0);
    iVar4 = iVar6 * 4;
    iVar7 = 0x21 - iVar6;
    if (iVar6 < 0x21) {
      do {
        iVar6 = (&DAT_803dd184)[param_1] + iVar4;
        *(float *)(iVar6 + 0x70) =
             FLOAT_803db414 * *(float *)(iVar6 + 0x178) + *(float *)(iVar6 + 0x70);
        iVar4 = iVar4 + 4;
        iVar7 = iVar7 + -1;
      } while (iVar7 != 0);
    }
    iVar6 = 0;
    iVar4 = 0;
    iVar7 = 3;
    do {
      iVar5 = (&DAT_803dd184)[param_1] + iVar4;
      *(float *)(iVar5 + 0x1fc) =
           FLOAT_803db414 * *(float *)(iVar5 + 0x2ac) + *(float *)(iVar5 + 0x1fc);
      iVar5 = (&DAT_803dd184)[param_1] + iVar4;
      *(float *)(iVar5 + 0x200) =
           FLOAT_803db414 * *(float *)(iVar5 + 0x2b0) + *(float *)(iVar5 + 0x200);
      iVar5 = (&DAT_803dd184)[param_1] + iVar4;
      *(float *)(iVar5 + 0x204) =
           FLOAT_803db414 * *(float *)(iVar5 + 0x2b4) + *(float *)(iVar5 + 0x204);
      iVar5 = (&DAT_803dd184)[param_1] + iVar4;
      *(float *)(iVar5 + 0x208) =
           FLOAT_803db414 * *(float *)(iVar5 + 0x2b8) + *(float *)(iVar5 + 0x208);
      iVar5 = (&DAT_803dd184)[param_1] + iVar4;
      *(float *)(iVar5 + 0x20c) =
           FLOAT_803db414 * *(float *)(iVar5 + 700) + *(float *)(iVar5 + 0x20c);
      iVar5 = (&DAT_803dd184)[param_1] + iVar4;
      *(float *)(iVar5 + 0x210) =
           FLOAT_803db414 * *(float *)(iVar5 + 0x2c0) + *(float *)(iVar5 + 0x210);
      iVar5 = (&DAT_803dd184)[param_1] + iVar4;
      *(float *)(iVar5 + 0x214) =
           FLOAT_803db414 * *(float *)(iVar5 + 0x2c4) + *(float *)(iVar5 + 0x214);
      iVar4 = iVar4 + 0x1c;
      iVar6 = iVar6 + 7;
      iVar7 = iVar7 + -1;
    } while (iVar7 != 0);
    iVar4 = iVar6 * 4;
    iVar7 = 0x16 - iVar6;
    if (iVar6 < 0x16) {
      do {
        iVar6 = (&DAT_803dd184)[param_1] + iVar4;
        *(float *)(iVar6 + 0x1fc) =
             FLOAT_803db414 * *(float *)(iVar6 + 0x2ac) + *(float *)(iVar6 + 0x1fc);
        iVar4 = iVar4 + 4;
        iVar7 = iVar7 + -1;
      } while (iVar7 != 0);
    }
    iVar4 = (&DAT_803dd184)[param_1];
    *(float *)(iVar4 + 0x304) =
         FLOAT_803db414 * *(float *)(iVar4 + 0x308) + *(float *)(iVar4 + 0x304);
    fVar3 = FLOAT_803df118;
    fVar2 = FLOAT_803df108;
    iVar4 = (&DAT_803dd184)[param_1];
    uVar1 = *(ushort *)(iVar4 + 4);
    if (((uVar1 & 1) == 0) || (*(float *)(iVar4 + 0x310) <= FLOAT_803df108)) {
      if (((uVar1 & 4) == 0) || (FLOAT_803df118 <= *(float *)(iVar4 + 0x310))) {
        if (((uVar1 & 1) == 0) && (*(float *)(iVar4 + 0x310) < FLOAT_803df118)) {
          *(float *)(iVar4 + 0x310) = FLOAT_803df118 * *(float *)(iVar4 + 0x304);
          if (fVar3 < *(float *)((&DAT_803dd184)[param_1] + 0x310)) {
            *(float *)((&DAT_803dd184)[param_1] + 0x310) = fVar3;
          }
        }
      }
      else {
        *(float *)(iVar4 + 0x310) = FLOAT_803df118 * *(float *)(iVar4 + 0x304);
        if (fVar3 < *(float *)((&DAT_803dd184)[param_1] + 0x310)) {
          *(float *)((&DAT_803dd184)[param_1] + 0x310) = fVar3;
        }
      }
    }
    else {
      *(float *)(iVar4 + 0x310) =
           -(FLOAT_803df118 * *(float *)(iVar4 + 0x304) - *(float *)(iVar4 + 0x310));
      if (*(float *)((&DAT_803dd184)[param_1] + 0x310) < fVar2) {
        *(float *)((&DAT_803dd184)[param_1] + 0x310) = fVar2;
        DAT_803db750 = 1;
      }
    }
    *(undefined4 *)((&DAT_803dd184)[param_1] + 0x30c) =
         *(undefined4 *)((&DAT_803dd184)[param_1] + 0x304);
  }
  return;
}

