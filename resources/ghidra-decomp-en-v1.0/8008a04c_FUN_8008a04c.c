// Function: FUN_8008a04c
// Entry: 8008a04c
// Size: 1204 bytes

/* WARNING: Removing unreachable block (ram,0x8008a4d8) */
/* WARNING: Removing unreachable block (ram,0x8008a4d0) */
/* WARNING: Removing unreachable block (ram,0x8008a4e0) */

void FUN_8008a04c(void)

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
  undefined4 uVar11;
  double dVar12;
  undefined8 in_f29;
  double dVar13;
  undefined8 in_f30;
  double dVar14;
  undefined8 in_f31;
  double dVar15;
  double local_d8;
  double local_d0;
  double local_c8;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar11 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  FUN_802860b4();
  if (DAT_803dd12c == 0) {
    iVar8 = 0;
    do {
      FUN_80089a60((double)DAT_8030f2c8,(double)DAT_8030f2cc,(double)DAT_8030f2d0,iVar8,0xff,0xff,
                   0xff,0xff,0xff,0xff);
      iVar8 = iVar8 + 1;
    } while (iVar8 < 3);
  }
  else {
    fVar2 = *(float *)(DAT_803dd12c + 0x20c) / FLOAT_803df078;
    fVar3 = FLOAT_803df058;
    if ((FLOAT_803df058 <= fVar2) && (fVar3 = fVar2, FLOAT_803df05c < fVar2)) {
      fVar3 = FLOAT_803df05c;
    }
    if (FLOAT_803df07c < fVar3) {
      if (FLOAT_803df068 < fVar3) {
        if (FLOAT_803df080 < fVar3) {
          dVar14 = (double)((fVar3 - FLOAT_803df080) / FLOAT_803df07c);
          iVar8 = 3;
        }
        else {
          dVar14 = (double)((fVar3 - FLOAT_803df068) / FLOAT_803df07c);
          iVar8 = 2;
        }
      }
      else {
        dVar14 = (double)((fVar3 - FLOAT_803df07c) / FLOAT_803df07c);
        iVar8 = 1;
      }
    }
    else {
      dVar14 = (double)(fVar3 / FLOAT_803df07c);
      iVar8 = 0;
    }
    iVar9 = 0;
    iVar10 = 0;
    iVar1 = iVar8 * 4;
    dVar15 = (double)FLOAT_803df058;
    dVar13 = (double)FLOAT_803df084;
    do {
      if (-1 < *(char *)(DAT_803dd12c + iVar10 + 0xc1)) {
        FUN_80010c50(dVar14,&DAT_8030f308 + iVar1,0);
        FUN_80010c50(dVar14,&DAT_8030f2e0 + iVar1,0);
        FUN_80010c50(dVar14,&DAT_8030f2f4 + iVar1,0);
      }
      dVar12 = (double)FUN_80010c64(dVar14,DAT_803dd12c + iVar10 + iVar1 + 0x20,0);
      uVar5 = (uint)dVar12;
      dVar12 = (double)FUN_80010c64(dVar14,DAT_803dd12c + iVar10 + (iVar8 + 7) * 4 + 0x20,0);
      uVar6 = (uint)dVar12;
      dVar12 = (double)FUN_80010c64(dVar14,DAT_803dd12c + iVar10 + (iVar8 + 0xe) * 4 + 0x20,0);
      uVar7 = (uint)dVar12;
      iVar4 = DAT_803dd12c + iVar10;
      dVar12 = (double)*(float *)(iVar4 + 0xb8);
      if (dVar12 != dVar15) {
        local_c8 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar4 + 0x74));
        local_d0 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
        local_d8 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
        uVar5 = (uint)(dVar12 * (double)((float)(local_c8 - DOUBLE_803df070) -
                                        (float)(local_d0 - DOUBLE_803df090)) +
                      (double)(float)(local_d8 - DOUBLE_803df090));
        uVar6 = (uint)(dVar12 * (double)((float)((double)CONCAT44(0x43300000,
                                                                  (uint)*(byte *)(iVar4 + 0x75)) -
                                                DOUBLE_803df070) -
                                        (float)((double)CONCAT44(0x43300000,uVar6 ^ 0x80000000) -
                                               DOUBLE_803df090)) +
                      (double)(float)((double)CONCAT44(0x43300000,uVar6 ^ 0x80000000) -
                                     DOUBLE_803df090));
        uVar7 = (uint)(dVar12 * (double)((float)((double)CONCAT44(0x43300000,
                                                                  (uint)*(byte *)(iVar4 + 0x76)) -
                                                DOUBLE_803df070) -
                                        (float)((double)CONCAT44(0x43300000,uVar7 ^ 0x80000000) -
                                               DOUBLE_803df090)) +
                      (double)(float)((double)CONCAT44(0x43300000,uVar7 ^ 0x80000000) -
                                     DOUBLE_803df090));
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
        DAT_803dd178 = (undefined)uVar5;
        uRam803dd179 = (undefined)uVar6;
        uRam803dd17a = (undefined)uVar7;
      }
      if (((double)*(float *)(DAT_803dd12c + 0x20c) < dVar13) ||
         ((double)FLOAT_803df088 < (double)*(float *)(DAT_803dd12c + 0x20c))) {
        FUN_80089a60(-(double)DAT_8030f2d4,(double)DAT_8030f2d8,-(double)DAT_8030f2dc,iVar9);
      }
      else {
        FUN_80089a60((double)DAT_8030f2c8,(double)DAT_8030f2cc,(double)DAT_8030f2d0,iVar9);
      }
      iVar10 = iVar10 + 0xa4;
      iVar9 = iVar9 + 1;
    } while (iVar9 < 2);
    dVar14 = (double)FLOAT_803df058;
    FUN_80089a60(dVar14,dVar14,dVar14,2,0xff,0xff,0xff,0xff,0xff,0xff);
  }
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  __psq_l0(auStack24,uVar11);
  __psq_l1(auStack24,uVar11);
  __psq_l0(auStack40,uVar11);
  __psq_l1(auStack40,uVar11);
  FUN_80286100();
  return;
}

