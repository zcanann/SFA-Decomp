// Function: FUN_8008a2d8
// Entry: 8008a2d8
// Size: 1204 bytes

/* WARNING: Removing unreachable block (ram,0x8008a76c) */
/* WARNING: Removing unreachable block (ram,0x8008a764) */
/* WARNING: Removing unreachable block (ram,0x8008a75c) */
/* WARNING: Removing unreachable block (ram,0x8008a2f8) */
/* WARNING: Removing unreachable block (ram,0x8008a2f0) */
/* WARNING: Removing unreachable block (ram,0x8008a2e8) */

void FUN_8008a2d8(void)

{
  int iVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  undefined uVar11;
  int iVar12;
  int iVar13;
  double dVar14;
  double dVar15;
  double dVar16;
  double dVar17;
  undefined8 local_d8;
  undefined8 local_d0;
  undefined8 local_c8;
  
  FUN_80286818();
  if (DAT_803dddac == 0) {
    iVar8 = 0;
    do {
      FUN_80089cec((double)DAT_8030fe88,(double)DAT_8030fe8c,(double)DAT_8030fe90,iVar8,0xff,0xff,
                   0xff,0xff,0xff,0xff);
      iVar8 = iVar8 + 1;
    } while (iVar8 < 3);
  }
  else {
    fVar2 = *(float *)(DAT_803dddac + 0x20c) / FLOAT_803dfcf8;
    fVar3 = FLOAT_803dfcd8;
    if ((FLOAT_803dfcd8 <= fVar2) && (fVar3 = fVar2, FLOAT_803dfcdc < fVar2)) {
      fVar3 = FLOAT_803dfcdc;
    }
    if (FLOAT_803dfcfc < fVar3) {
      if (FLOAT_803dfce8 < fVar3) {
        if (FLOAT_803dfd00 < fVar3) {
          dVar16 = (double)((fVar3 - FLOAT_803dfd00) / FLOAT_803dfcfc);
          iVar8 = 3;
        }
        else {
          dVar16 = (double)((fVar3 - FLOAT_803dfce8) / FLOAT_803dfcfc);
          iVar8 = 2;
        }
      }
      else {
        dVar16 = (double)((fVar3 - FLOAT_803dfcfc) / FLOAT_803dfcfc);
        iVar8 = 1;
      }
    }
    else {
      dVar16 = (double)(fVar3 / FLOAT_803dfcfc);
      iVar8 = 0;
    }
    iVar9 = 0;
    iVar10 = 0;
    iVar1 = iVar8 * 4;
    dVar17 = (double)FLOAT_803dfcd8;
    dVar15 = (double)FLOAT_803dfd04;
    do {
      if (*(char *)(DAT_803dddac + iVar10 + 0xc1) < '\0') {
        uVar11 = 200;
        iVar12 = 0;
        iVar13 = 0x60;
      }
      else {
        dVar14 = FUN_80010c70(dVar16,(float *)(&DAT_8030fec8 + iVar1));
        uVar11 = (undefined)(int)dVar14;
        dVar14 = FUN_80010c70(dVar16,(float *)(&DAT_8030fea0 + iVar1));
        iVar12 = (int)dVar14;
        dVar14 = FUN_80010c70(dVar16,(float *)(&DAT_8030feb4 + iVar1));
        iVar13 = (int)dVar14;
      }
      dVar14 = FUN_80010c84(dVar16,(float *)(DAT_803dddac + iVar10 + iVar1 + 0x20),(float *)0x0);
      uVar5 = (uint)dVar14;
      dVar14 = FUN_80010c84(dVar16,(float *)(DAT_803dddac + iVar10 + (iVar8 + 7) * 4 + 0x20),
                            (float *)0x0);
      uVar6 = (uint)dVar14;
      dVar14 = FUN_80010c84(dVar16,(float *)(DAT_803dddac + iVar10 + (iVar8 + 0xe) * 4 + 0x20),
                            (float *)0x0);
      uVar7 = (uint)dVar14;
      iVar4 = DAT_803dddac + iVar10;
      dVar14 = (double)*(float *)(iVar4 + 0xb8);
      if (dVar14 != dVar17) {
        local_c8 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar4 + 0x74));
        local_d0 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
        local_d8 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
        uVar5 = (uint)(dVar14 * (double)((float)(local_c8 - DOUBLE_803dfcf0) -
                                        (float)(local_d0 - DOUBLE_803dfd10)) +
                      (double)(float)(local_d8 - DOUBLE_803dfd10));
        uVar6 = (uint)(dVar14 * (double)((float)((double)CONCAT44(0x43300000,
                                                                  (uint)*(byte *)(iVar4 + 0x75)) -
                                                DOUBLE_803dfcf0) -
                                        (float)((double)CONCAT44(0x43300000,uVar6 ^ 0x80000000) -
                                               DOUBLE_803dfd10)) +
                      (double)(float)((double)CONCAT44(0x43300000,uVar6 ^ 0x80000000) -
                                     DOUBLE_803dfd10));
        uVar7 = (uint)(dVar14 * (double)((float)((double)CONCAT44(0x43300000,
                                                                  (uint)*(byte *)(iVar4 + 0x76)) -
                                                DOUBLE_803dfcf0) -
                                        (float)((double)CONCAT44(0x43300000,uVar7 ^ 0x80000000) -
                                               DOUBLE_803dfd10)) +
                      (double)(float)((double)CONCAT44(0x43300000,uVar7 ^ 0x80000000) -
                                     DOUBLE_803dfd10));
      }
      if ((int)uVar5 < 0) {
        uVar5 = 0;
      }
      else if (0xff < (int)uVar5) {
        uVar5 = 0xff;
      }
      if ((int)uVar6 < 0) {
        uVar6 = 0;
      }
      else if (0xff < (int)uVar6) {
        uVar6 = 0xff;
      }
      if ((int)uVar7 < 0) {
        uVar7 = 0;
      }
      else if (0xff < (int)uVar7) {
        uVar7 = 0xff;
      }
      if (iVar9 == 0) {
        DAT_803dddf8 = (undefined)uVar5;
        uRam803dddf9 = (undefined)uVar6;
        uRam803dddfa = (undefined)uVar7;
      }
      if (((double)*(float *)(DAT_803dddac + 0x20c) < dVar15) ||
         ((double)FLOAT_803dfd08 < (double)*(float *)(DAT_803dddac + 0x20c))) {
        FUN_80089cec(-(double)DAT_8030fe94,(double)DAT_8030fe98,-(double)DAT_8030fe9c,iVar9,uVar5,
                     uVar6,uVar7,iVar12,iVar13,uVar11);
      }
      else {
        FUN_80089cec((double)DAT_8030fe88,(double)DAT_8030fe8c,(double)DAT_8030fe90,iVar9,uVar5,
                     uVar6,uVar7,iVar12,iVar13,uVar11);
      }
      iVar10 = iVar10 + 0xa4;
      iVar9 = iVar9 + 1;
    } while (iVar9 < 2);
    dVar16 = (double)FLOAT_803dfcd8;
    FUN_80089cec(dVar16,dVar16,dVar16,2,0xff,0xff,0xff,0xff,0xff,0xff);
  }
  FUN_80286864();
  return;
}

