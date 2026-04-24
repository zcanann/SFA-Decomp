// Function: FUN_8006d764
// Entry: 8006d764
// Size: 5948 bytes

/* WARNING: Removing unreachable block (ram,0x8006ee80) */
/* WARNING: Removing unreachable block (ram,0x8006ee78) */
/* WARNING: Removing unreachable block (ram,0x8006ee70) */
/* WARNING: Removing unreachable block (ram,0x8006ee68) */
/* WARNING: Removing unreachable block (ram,0x8006ee60) */
/* WARNING: Removing unreachable block (ram,0x8006ee58) */
/* WARNING: Removing unreachable block (ram,0x8006ee50) */
/* WARNING: Removing unreachable block (ram,0x8006ee48) */
/* WARNING: Removing unreachable block (ram,0x8006ee40) */
/* WARNING: Removing unreachable block (ram,0x8006ee38) */
/* WARNING: Removing unreachable block (ram,0x8006ee30) */
/* WARNING: Removing unreachable block (ram,0x8006ee28) */
/* WARNING: Removing unreachable block (ram,0x8006ee20) */
/* WARNING: Removing unreachable block (ram,0x8006ee18) */
/* WARNING: Removing unreachable block (ram,0x8006ee10) */
/* WARNING: Removing unreachable block (ram,0x8006ee08) */
/* WARNING: Removing unreachable block (ram,0x8006d7ec) */
/* WARNING: Removing unreachable block (ram,0x8006d7e4) */
/* WARNING: Removing unreachable block (ram,0x8006d7dc) */
/* WARNING: Removing unreachable block (ram,0x8006d7d4) */
/* WARNING: Removing unreachable block (ram,0x8006d7cc) */
/* WARNING: Removing unreachable block (ram,0x8006d7c4) */
/* WARNING: Removing unreachable block (ram,0x8006d7bc) */
/* WARNING: Removing unreachable block (ram,0x8006d7b4) */
/* WARNING: Removing unreachable block (ram,0x8006d7ac) */
/* WARNING: Removing unreachable block (ram,0x8006d7a4) */
/* WARNING: Removing unreachable block (ram,0x8006d79c) */
/* WARNING: Removing unreachable block (ram,0x8006d794) */
/* WARNING: Removing unreachable block (ram,0x8006d78c) */
/* WARNING: Removing unreachable block (ram,0x8006d784) */
/* WARNING: Removing unreachable block (ram,0x8006d77c) */
/* WARNING: Removing unreachable block (ram,0x8006d774) */

void FUN_8006d764(void)

{
  int iVar1;
  int iVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  int iVar6;
  float fVar7;
  float fVar8;
  char cVar9;
  float fVar10;
  ushort uVar11;
  int iVar12;
  float fVar13;
  undefined uVar14;
  uint uVar15;
  int iVar16;
  undefined4 uVar17;
  undefined4 uVar18;
  uint uVar19;
  undefined4 uVar20;
  uint uVar21;
  uint uVar22;
  undefined4 uVar23;
  undefined4 uVar24;
  undefined4 uVar25;
  undefined *puVar26;
  int iVar27;
  int iVar28;
  double dVar29;
  double dVar30;
  double dVar31;
  double dVar32;
  double dVar33;
  double dVar34;
  double dVar35;
  longlong lVar36;
  double dVar37;
  double dVar38;
  double dVar39;
  double dVar40;
  double dVar41;
  double dVar42;
  double dVar43;
  double dVar44;
  double dVar45;
  double dVar46;
  double dVar47;
  double dVar48;
  double dVar49;
  double dVar50;
  undefined8 local_158;
  undefined8 local_150;
  undefined8 local_148;
  
  FUN_80286834();
  puVar26 = &DAT_8038eba8;
  uVar15 = FUN_80022e00(1);
  DAT_803925b8 = FUN_80054e14(0x100,0x100,0,'\0',0,0,0,1,1);
  DAT_803925bc = FUN_80054e14(0x100,0x100,1,'\0',0,0,0,0,0);
  DAT_803925c0 = DAT_803925bc;
  DAT_803925c4 = DAT_803925bc;
  DAT_803925c8 = DAT_803925bc;
  DAT_803925cc = DAT_803925bc;
  DAT_803925d0 = DAT_803925bc;
  DAT_803925d4 = DAT_803925bc;
  FUN_800033a8(DAT_803925b8 + 0x60,0,*(uint *)(DAT_803925b8 + 0x44));
  FUN_802420e0(DAT_803925b8 + 0x60,*(int *)(DAT_803925b8 + 0x44));
  DAT_803ddbfc = FUN_80054e14(0x140,0xf0,4,'\0',0,0,0,1,1);
  DAT_803ddc64 = FUN_80054e14(0x50,0x3c,4,'\0',0,0,0,1,1);
  DAT_803ddc5c = FUN_80054e14(0x140,0xf0,1,'\0',0,0,0,1,1);
  DAT_803ddc58 = FUN_80054e14(0x20,0x20,1,'\0',0,0,0,1,1);
  fVar8 = FLOAT_803dfa6c;
  fVar10 = FLOAT_803dfa50;
  dVar41 = DOUBLE_803dfa48;
  fVar13 = FLOAT_803df9ac;
  fVar5 = FLOAT_803df988;
  uVar19 = 0;
  dVar38 = (double)FLOAT_803dfa70;
  do {
    uVar21 = 0;
    local_158 = (double)CONCAT44(0x43300000,uVar19 ^ 0x80000000);
    fVar7 = (float)(local_158 - dVar41) - fVar8;
    iVar16 = (uVar19 & 7) + ((int)uVar19 >> 3) * 0x20;
    iVar27 = 0x10;
    do {
      local_158 = (double)CONCAT44(0x43300000,uVar21 ^ 0x80000000);
      fVar3 = (float)((double)(fVar7 * fVar10) * dVar38);
      fVar4 = (float)((double)(((float)(local_158 - dVar41) - fVar8) * fVar10) * dVar38);
      fVar4 = fVar3 * fVar3 + fVar4 * fVar4;
      fVar3 = FLOAT_803df9a8;
      if (fVar4 <= fVar13) {
        fVar3 = fVar13 - fVar4;
      }
      *(char *)(DAT_803ddc58 + iVar16 + (uVar21 & 3) * 8 + ((int)uVar21 >> 2) * 0x80 + 0x60) =
           (char)(int)(fVar5 * fVar3);
      uVar22 = uVar21 + 1;
      local_158 = (double)CONCAT44(0x43300000,uVar22 ^ 0x80000000);
      fVar3 = (float)((double)(fVar7 * fVar10) * dVar38);
      fVar4 = (float)((double)(((float)(local_158 - dVar41) - fVar8) * fVar10) * dVar38);
      fVar4 = fVar3 * fVar3 + fVar4 * fVar4;
      fVar3 = FLOAT_803df9a8;
      if (fVar4 <= fVar13) {
        fVar3 = fVar13 - fVar4;
      }
      *(char *)(DAT_803ddc58 + iVar16 + (uVar22 & 3) * 8 + ((int)uVar22 >> 2) * 0x80 + 0x60) =
           (char)(int)(fVar5 * fVar3);
      uVar21 = uVar21 + 2;
      iVar27 = iVar27 + -1;
    } while (iVar27 != 0);
    uVar19 = uVar19 + 1;
  } while ((int)uVar19 < 0x20);
  FUN_802420e0(DAT_803ddc58 + 0x60,*(int *)(DAT_803ddc58 + 0x44));
  DAT_803ddc54 = FUN_80054e14(0x10,0x10,1,'\0',0,0,0,1,1);
  fVar10 = FLOAT_803dfa74;
  dVar41 = DOUBLE_803dfa48;
  fVar13 = FLOAT_803df9c0;
  fVar5 = FLOAT_803df9ac;
  uVar19 = 0;
  dVar40 = (double)FLOAT_803df990;
  dVar29 = (double)FLOAT_803df988;
  do {
    uVar21 = 0;
    local_150 = (double)CONCAT44(0x43300000,uVar19 ^ 0x80000000);
    dVar45 = local_150 - dVar41;
    iVar16 = 0x10;
    do {
      local_150 = (double)CONCAT44(0x43300000,uVar21 ^ 0x80000000);
      fVar8 = (float)((double)(float)dVar45 - dVar40) * fVar13 * fVar10;
      fVar7 = (float)((double)(float)(local_150 - dVar41) - dVar40) * fVar13 * fVar10;
      fVar8 = fVar8 * fVar8 + fVar7 * fVar7;
      if (fVar8 <= fVar5) {
        dVar42 = (double)(fVar5 - fVar8);
        if ((double)FLOAT_803df9a8 < dVar42) {
          dVar38 = 1.0 / SQRT(dVar42);
          dVar38 = DOUBLE_803df9d8 * dVar38 * -(dVar42 * dVar38 * dVar38 - DOUBLE_803df9e0);
          dVar38 = DOUBLE_803df9d8 * dVar38 * -(dVar42 * dVar38 * dVar38 - DOUBLE_803df9e0);
          dVar42 = (double)(float)(dVar42 * DOUBLE_803df9d8 * dVar38 *
                                            -(dVar42 * dVar38 * dVar38 - DOUBLE_803df9e0));
          dVar38 = DOUBLE_803df9e0;
        }
      }
      else {
        dVar42 = (double)FLOAT_803df9a8;
      }
      *(char *)(DAT_803ddc54 +
               (uVar19 & 7) + ((int)uVar19 >> 3) * 0x20 + (uVar21 & 3) * 8 +
               ((int)uVar21 >> 2) * 0x40 + 0x60) = (char)(int)(dVar29 * dVar42);
      uVar21 = uVar21 + 1;
      iVar16 = iVar16 + -1;
    } while (iVar16 != 0);
    uVar19 = uVar19 + 1;
  } while ((int)uVar19 < 0x10);
  FUN_802420e0(DAT_803ddc54 + 0x60,*(int *)(DAT_803ddc54 + 0x44));
  uVar17 = 5;
  uVar18 = 0;
  uVar20 = 0;
  uVar23 = 0;
  uVar24 = 0;
  uVar25 = 1;
  DAT_803ddc50 = FUN_80054e14(0x40,0x40,5,'\0',0,0,0,1,1);
  dVar29 = (double)FLOAT_803df9a8;
  uVar19 = 0;
  dVar49 = (double)FLOAT_803dfa7c;
  dVar47 = (double)FLOAT_803dfa78;
  dVar45 = dVar29;
  dVar42 = dVar29;
  dVar46 = dVar29;
  dVar48 = DOUBLE_803dfa48;
  do {
    uVar21 = 0;
    local_150 = (double)CONCAT44(0x43300000,uVar19 ^ 0x80000000);
    local_158 = (double)CONCAT44(0x43300000,uVar19 + 1 ^ 0x80000000);
    dVar50 = (double)(float)((double)(float)((double)(float)(local_150 - dVar48) - dVar47) * dVar49)
    ;
    dVar43 = (double)(float)((double)(float)((double)(float)(local_158 - dVar48) - dVar47) * dVar49)
    ;
    do {
      local_150 = (double)CONCAT44(0x43300000,uVar21 ^ 0x80000000);
      fVar5 = (float)((double)(float)((double)(float)(local_150 - dVar48) - dVar47) * dVar49);
      dVar39 = (double)(fVar5 * fVar5);
      if (dVar46 < (double)(float)(dVar50 * dVar50 + dVar39)) {
        dVar38 = DOUBLE_803df9e0;
      }
      if (dVar42 < (double)(float)(dVar43 * dVar43 + dVar39)) {
        dVar38 = DOUBLE_803df9e0;
      }
      local_150 = (double)CONCAT44(0x43300000,uVar21 + 1 ^ 0x80000000);
      fVar5 = (float)((double)(float)((double)(float)(local_150 - dVar48) - dVar47) * dVar49);
      if (dVar45 < (double)(float)(dVar50 * dVar50 + (double)(fVar5 * fVar5))) {
        dVar38 = DOUBLE_803df9e0;
      }
      dVar30 = (double)FUN_80294b54();
      dVar30 = -dVar30;
      dVar31 = (double)FUN_80294b54();
      dVar31 = ABS(dVar31);
      dVar32 = (double)FUN_80294b54();
      if (dVar29 < (double)(float)(dVar30 - (double)(float)dVar31)) {
        dVar29 = (double)(float)(dVar30 - (double)(float)dVar31);
      }
      if (dVar29 < (double)(float)(dVar30 - (double)(float)ABS(dVar32))) {
        dVar29 = (double)(float)(dVar30 - (double)(float)ABS(dVar32));
      }
      uVar21 = uVar21 + 1;
    } while ((int)uVar21 < 0x40);
    uVar19 = uVar19 + 1;
  } while ((int)uVar19 < 0x40);
  dVar45 = (double)FLOAT_803df9ac;
  dVar50 = (double)(float)(dVar45 / dVar29);
  uVar19 = 0;
  dVar42 = (double)FLOAT_803dfa7c;
  dVar46 = (double)FLOAT_803dfa78;
  dVar48 = (double)FLOAT_803df9a8;
  dVar47 = (double)FLOAT_803dfa40;
  dVar49 = (double)FLOAT_803dfa84;
  dVar43 = (double)FLOAT_803dfa50;
  dVar29 = DOUBLE_803dfa48;
  do {
    uVar21 = 0;
    local_150 = (double)CONCAT44(0x43300000,uVar19 ^ 0x80000000);
    local_158 = (double)CONCAT44(0x43300000,uVar19 + 1 ^ 0x80000000);
    dVar31 = (double)(float)((double)(float)((double)(float)(local_150 - dVar29) - dVar46) * dVar42)
    ;
    dVar30 = (double)(float)((double)(float)((double)(float)(local_158 - dVar29) - dVar46) * dVar42)
    ;
    do {
      iVar16 = DAT_803ddc50 + (uVar19 & 3) * 2;
      local_150 = (double)CONCAT44(0x43300000,uVar21 ^ 0x80000000);
      fVar5 = (float)((double)(float)((double)(float)(local_150 - dVar29) - dVar46) * dVar42);
      dVar32 = (double)(fVar5 * fVar5);
      dVar44 = (double)(float)(dVar31 * dVar31 + dVar32);
      if (dVar48 < dVar44) {
        dVar38 = 1.0 / SQRT(dVar44);
        dVar38 = DOUBLE_803df9d8 * dVar38 * -(dVar44 * dVar38 * dVar38 - DOUBLE_803df9e0);
        dVar38 = DOUBLE_803df9d8 * dVar38 * -(dVar44 * dVar38 * dVar38 - DOUBLE_803df9e0);
        dVar44 = (double)(float)(dVar44 * DOUBLE_803df9d8 * dVar38 *
                                          -(dVar44 * dVar38 * dVar38 - DOUBLE_803df9e0));
        dVar38 = DOUBLE_803df9d8;
      }
      if (dVar48 < (double)(float)(dVar30 * dVar30 + dVar32)) {
        dVar38 = DOUBLE_803df9d8;
      }
      local_150 = (double)CONCAT44(0x43300000,uVar21 + 1 ^ 0x80000000);
      fVar5 = (float)((double)(float)((double)(float)(local_150 - dVar29) - dVar46) * dVar42);
      if (dVar48 < (double)(float)(dVar31 * dVar31 + (double)(fVar5 * fVar5))) {
        dVar38 = DOUBLE_803df9d8;
      }
      dVar33 = (double)FUN_80294b54();
      dVar33 = -dVar33;
      dVar34 = (double)FUN_80294b54();
      dVar34 = -dVar34;
      dVar35 = (double)FUN_80294b54();
      if (dVar45 <= dVar44) {
        dVar44 = (double)FLOAT_803df9a8;
      }
      else {
        dVar44 = (double)(float)(dVar45 - dVar44);
        if ((double)FLOAT_803df9a8 < dVar44) {
          dVar38 = 1.0 / SQRT(dVar44);
          dVar38 = DOUBLE_803df9d8 * dVar38 * -(dVar44 * dVar38 * dVar38 - DOUBLE_803df9e0);
          dVar39 = DOUBLE_803df9d8 * dVar38 * -(dVar44 * dVar38 * dVar38 - DOUBLE_803df9e0);
          dVar38 = DOUBLE_803df9d8 * dVar39;
          dVar44 = (double)(float)(dVar44 * dVar38 * -(dVar44 * dVar39 * dVar39 - DOUBLE_803df9e0));
          dVar32 = DOUBLE_803df9e0;
          dVar39 = DOUBLE_803df9d8;
        }
      }
      dVar37 = (double)(float)(dVar46 * dVar44);
      if (dVar49 < (double)(float)(dVar46 * dVar44)) {
        dVar37 = dVar49;
      }
      lVar36 = (longlong)(int)dVar37;
      *(ushort *)
       (iVar16 + ((int)uVar19 >> 2) * 0x20 + (uVar21 & 3) * 8 + ((int)uVar21 >> 2) * 0x200 + 0x60) =
           (ushort)(int)((double)(float)(dVar50 * (double)(float)(dVar47 * (double)(float)(dVar33 - 
                                                  -dVar35)) + dVar47) * dVar43) & 0xf |
           (ushort)(((int)dVar37 & 0xfU) << 4) |
           (ushort)(((int)((double)(float)(dVar50 * (double)(float)(dVar47 * (double)(float)(dVar33 
                                                  - dVar34)) + dVar47) * dVar42) & 7U) << 0xc);
      uVar21 = uVar21 + 1;
    } while ((int)uVar21 < 0x40);
    uVar19 = uVar19 + 1;
  } while ((int)uVar19 < 0x40);
  iVar16 = *(int *)(DAT_803ddc50 + 0x44);
  FUN_802420e0(DAT_803ddc50 + 0x60,iVar16);
  DAT_803ddc4c = FUN_80054ed0(lVar36,dVar37,dVar38,dVar32,dVar39,dVar44,dVar40,dVar41,0x5b0,iVar16,
                              uVar17,uVar18,uVar20,uVar23,uVar24,uVar25);
  DAT_803ddc48 = FUN_80054ed0(lVar36,dVar37,dVar38,dVar32,dVar39,dVar44,dVar40,dVar41,0x600,iVar16,
                              uVar17,uVar18,uVar20,uVar23,uVar24,uVar25);
  DAT_803ddc44 = FUN_80054ed0(lVar36,dVar37,dVar38,dVar32,dVar39,dVar44,dVar40,dVar41,0xc18,iVar16,
                              uVar17,uVar18,uVar20,uVar23,uVar24,uVar25);
  DAT_803ddc1c = FUN_80054e14(0x100,4,1,'\0',0,0,0,0,0);
  uVar19 = 0;
  iVar16 = 0x80;
  do {
    uVar21 = uVar19 & 7;
    iVar27 = ((int)uVar19 >> 3) * 0x20;
    uVar14 = (undefined)uVar19;
    *(undefined *)(DAT_803ddc1c + uVar21 + iVar27 + 0x60) = uVar14;
    *(undefined *)(DAT_803ddc1c + uVar21 + iVar27 + 0x68) = uVar14;
    *(undefined *)(DAT_803ddc1c + uVar21 + iVar27 + 0x70) = uVar14;
    *(undefined *)(DAT_803ddc1c + uVar21 + iVar27 + 0x78) = uVar14;
    uVar22 = uVar19 + 1;
    uVar21 = uVar22 & 7;
    iVar27 = ((int)uVar22 >> 3) * 0x20;
    uVar14 = (undefined)uVar22;
    *(undefined *)(DAT_803ddc1c + uVar21 + iVar27 + 0x60) = uVar14;
    *(undefined *)(DAT_803ddc1c + uVar21 + iVar27 + 0x68) = uVar14;
    *(undefined *)(DAT_803ddc1c + uVar21 + iVar27 + 0x70) = uVar14;
    *(undefined *)(DAT_803ddc1c + uVar21 + iVar27 + 0x78) = uVar14;
    uVar19 = uVar19 + 2;
    iVar16 = iVar16 + -1;
  } while (iVar16 != 0);
  FUN_802420e0(DAT_803ddc1c + 0x60,*(int *)(DAT_803ddc1c + 0x44));
  DAT_803ddc18 = FUN_80054e14(0x100,4,1,'\0',0,0,0,1,1);
  uVar19 = 0;
  iVar16 = 0x80;
  do {
    uVar21 = uVar19 & 7;
    iVar27 = ((int)uVar19 >> 3) * 0x20;
    cVar9 = -1 - (char)uVar19;
    *(char *)(DAT_803ddc18 + uVar21 + iVar27 + 0x60) = cVar9;
    *(char *)(DAT_803ddc18 + uVar21 + iVar27 + 0x68) = cVar9;
    *(char *)(DAT_803ddc18 + uVar21 + iVar27 + 0x70) = cVar9;
    *(char *)(DAT_803ddc18 + uVar21 + iVar27 + 0x78) = cVar9;
    uVar22 = uVar19 + 1;
    uVar21 = uVar22 & 7;
    iVar27 = ((int)uVar22 >> 3) * 0x20;
    cVar9 = -1 - (char)uVar22;
    *(char *)(DAT_803ddc18 + uVar21 + iVar27 + 0x60) = cVar9;
    *(char *)(DAT_803ddc18 + uVar21 + iVar27 + 0x68) = cVar9;
    *(char *)(DAT_803ddc18 + uVar21 + iVar27 + 0x70) = cVar9;
    *(char *)(DAT_803ddc18 + uVar21 + iVar27 + 0x78) = cVar9;
    uVar19 = uVar19 + 2;
    iVar16 = iVar16 + -1;
  } while (iVar16 != 0);
  FUN_802420e0(DAT_803ddc18 + 0x60,*(int *)(DAT_803ddc18 + 0x44));
  DAT_803ddc10 = FUN_80054e14(0x80,0x80,1,'\0',0,0,0,1,1);
  fVar13 = FLOAT_803dfa60;
  dVar41 = DOUBLE_803dfa48;
  fVar5 = FLOAT_803df99c;
  uVar19 = 0;
  dVar29 = (double)FLOAT_803df9a8;
  dVar38 = (double)FLOAT_803df9b8;
  do {
    uVar21 = 0;
    local_148 = (double)CONCAT44(0x43300000,uVar19 ^ 0x80000000);
    fVar10 = ((float)(local_148 - dVar41) - fVar5) * fVar13;
    iVar16 = 0x80;
    do {
      local_148 = (double)CONCAT44(0x43300000,uVar21 ^ 0x80000000);
      fVar8 = ((float)(local_148 - dVar41) - fVar5) * fVar13;
      dVar40 = (double)(fVar10 * fVar10 + fVar8 * fVar8);
      if (dVar29 < dVar40) {
        dVar45 = 1.0 / SQRT(dVar40);
        dVar45 = DOUBLE_803df9d8 * dVar45 * -(dVar40 * dVar45 * dVar45 - DOUBLE_803df9e0);
        dVar45 = DOUBLE_803df9d8 * dVar45 * -(dVar40 * dVar45 * dVar45 - DOUBLE_803df9e0);
        dVar40 = (double)(float)(dVar40 * DOUBLE_803df9d8 * dVar45 *
                                          -(dVar40 * dVar45 * dVar45 - DOUBLE_803df9e0));
      }
      if (dVar38 <= dVar40) {
        if (dVar40 <= (double)FLOAT_803df9ac) {
          uVar14 = (undefined)
                   (int)(FLOAT_803dfa88 *
                        (float)((double)FLOAT_803df9ac -
                               (double)(float)((double)(float)(dVar40 - dVar38) / dVar38)));
        }
        else {
          uVar14 = 0;
        }
      }
      else {
        uVar14 = 0xa0;
      }
      *(undefined *)
       (DAT_803ddc10 +
       (uVar19 & 7) + ((int)uVar19 >> 3) * 0x20 + (uVar21 & 3) * 8 + ((int)uVar21 >> 2) * 0x200 +
       0x60) = uVar14;
      uVar21 = uVar21 + 1;
      iVar16 = iVar16 + -1;
    } while (iVar16 != 0);
    uVar19 = uVar19 + 1;
  } while ((int)uVar19 < 0x80);
  FUN_802420e0(DAT_803ddc10 + 0x60,*(int *)(DAT_803ddc10 + 0x44));
  DAT_803ddc40 = FUN_80054e14(0x80,0x80,1,'\0',0,0,0,1,1);
  fVar13 = FLOAT_803dfa60;
  dVar41 = DOUBLE_803dfa48;
  fVar5 = FLOAT_803df99c;
  uVar19 = 0;
  dVar40 = (double)FLOAT_803df9a8;
  dVar29 = (double)FLOAT_803df9ac;
  dVar38 = (double)FLOAT_803df988;
  do {
    uVar21 = 0;
    local_148 = (double)CONCAT44(0x43300000,uVar19 ^ 0x80000000);
    fVar10 = ABS(((float)(local_148 - dVar41) - fVar5) * fVar13);
    iVar16 = 0x80;
    do {
      local_148 = (double)CONCAT44(0x43300000,uVar21 ^ 0x80000000);
      fVar8 = ABS(((float)(local_148 - dVar41) - fVar5) * fVar13);
      dVar45 = (double)(fVar10 * fVar10 + fVar8 * fVar8);
      if (dVar40 < dVar45) {
        dVar42 = 1.0 / SQRT(dVar45);
        dVar42 = DOUBLE_803df9d8 * dVar42 * -(dVar45 * dVar42 * dVar42 - DOUBLE_803df9e0);
        dVar42 = DOUBLE_803df9d8 * dVar42 * -(dVar45 * dVar42 * dVar42 - DOUBLE_803df9e0);
        dVar45 = (double)(float)(dVar45 * DOUBLE_803df9d8 * dVar42 *
                                          -(dVar45 * dVar42 * dVar42 - DOUBLE_803df9e0));
      }
      dVar42 = (double)(float)(dVar29 - dVar45);
      if ((double)(float)(dVar29 - dVar45) < dVar40) {
        dVar42 = dVar40;
      }
      *(char *)(DAT_803ddc40 +
               (uVar19 & 7) + ((int)uVar19 >> 3) * 0x20 + (uVar21 & 3) * 8 +
               ((int)uVar21 >> 2) * 0x200 + 0x60) = (char)(int)(dVar38 * dVar42);
      uVar21 = uVar21 + 1;
      iVar16 = iVar16 + -1;
    } while (iVar16 != 0);
    uVar19 = uVar19 + 1;
  } while ((int)uVar19 < 0x80);
  FUN_802420e0(DAT_803ddc40 + 0x60,*(int *)(DAT_803ddc40 + 0x44));
  DAT_803ddc38 = FUN_80054e14(0x40,0x40,1,'\0',0,0,0,1,1);
  FUN_802420b0(DAT_803ddc38 + 0x60,*(int *)(DAT_803ddc38 + 0x44));
  FUN_8006a034(0);
  DAT_803ddc34 = FUN_80054e14(0x20,4,1,'\0',0,0,0,1,1);
  fVar10 = FLOAT_803dfa6c;
  fVar13 = FLOAT_803dfa50;
  dVar41 = DOUBLE_803dfa48;
  fVar5 = FLOAT_803df988;
  uVar19 = 0;
  dVar38 = (double)FLOAT_803df9a8;
  dVar29 = (double)FLOAT_803df9ac;
  do {
    uVar21 = 0;
    local_148 = (double)CONCAT44(0x43300000,uVar19 ^ 0x80000000);
    dVar40 = ABS((double)(((float)(local_148 - dVar41) - fVar10) * fVar13));
    iVar16 = 4;
    do {
      dVar45 = dVar40;
      if (dVar38 < dVar40) {
        dVar45 = 1.0 / SQRT(dVar40);
        dVar45 = DOUBLE_803df9d8 * dVar45 * -(dVar40 * dVar45 * dVar45 - DOUBLE_803df9e0);
        dVar45 = DOUBLE_803df9d8 * dVar45 * -(dVar40 * dVar45 * dVar45 - DOUBLE_803df9e0);
        dVar45 = (double)(float)(dVar40 * DOUBLE_803df9d8 * dVar45 *
                                          -(dVar40 * dVar45 * dVar45 - DOUBLE_803df9e0));
      }
      if (dVar38 < dVar45) {
        dVar42 = 1.0 / SQRT(dVar45);
        dVar42 = DOUBLE_803df9d8 * dVar42 * -(dVar45 * dVar42 * dVar42 - DOUBLE_803df9e0);
        dVar42 = DOUBLE_803df9d8 * dVar42 * -(dVar45 * dVar42 * dVar42 - DOUBLE_803df9e0);
        dVar45 = (double)(float)(dVar45 * DOUBLE_803df9d8 * dVar42 *
                                          -(dVar45 * dVar42 * dVar42 - DOUBLE_803df9e0));
      }
      *(char *)(DAT_803ddc34 +
               (uVar19 & 7) + ((int)uVar19 >> 3) * 0x20 + (uVar21 & 3) * 8 +
               ((int)uVar21 >> 2) * 0x80 + 0x60) = (char)(int)(fVar5 * (float)(dVar29 - dVar45));
      uVar21 = uVar21 + 1;
      iVar16 = iVar16 + -1;
    } while (iVar16 != 0);
    uVar19 = uVar19 + 1;
  } while ((int)uVar19 < 0x20);
  FUN_802420e0(DAT_803ddc34 + 0x60,*(int *)(DAT_803ddc34 + 0x44));
  DAT_803ddc30 = FUN_80054e14(0x80,0x80,1,'\0',0,1,1,1,1);
  fVar13 = FLOAT_803dfa60;
  dVar41 = DOUBLE_803dfa48;
  fVar5 = FLOAT_803df99c;
  uVar19 = 0;
  dVar29 = (double)FLOAT_803df9a8;
  dVar38 = (double)FLOAT_803df9bc;
  dVar40 = (double)FLOAT_803dfa6c;
  do {
    local_148 = (double)CONCAT44(0x43300000,uVar19 ^ 0x80000000);
    fVar10 = ((float)(local_148 - dVar41) - fVar5) * fVar13;
    uVar21 = 0;
    iVar16 = 0x80;
    do {
      local_148 = (double)CONCAT44(0x43300000,uVar21 ^ 0x80000000);
      fVar8 = ((float)(local_148 - dVar41) - fVar5) * fVar13;
      dVar45 = (double)(fVar8 * fVar8 + fVar10 * fVar10);
      if (dVar29 < dVar45) {
        dVar42 = 1.0 / SQRT(dVar45);
        dVar42 = DOUBLE_803df9d8 * dVar42 * -(dVar45 * dVar42 * dVar42 - DOUBLE_803df9e0);
        dVar42 = DOUBLE_803df9d8 * dVar42 * -(dVar45 * dVar42 * dVar42 - DOUBLE_803df9e0);
        dVar45 = (double)(float)(dVar45 * DOUBLE_803df9d8 * dVar42 *
                                          -(dVar45 * dVar42 * dVar42 - DOUBLE_803df9e0));
      }
      if ((dVar45 < dVar38) || ((double)FLOAT_803dfa8c < dVar45)) {
        dVar45 = (double)FLOAT_803df9a8;
      }
      else {
        fVar8 = FLOAT_803df9b4 * (float)(dVar45 - dVar38);
        if (fVar8 <= FLOAT_803df9b8) {
          fVar8 = FLOAT_803df9b8 - fVar8;
        }
        else {
          fVar8 = fVar8 - FLOAT_803df9b8;
        }
        dVar45 = -(double)(FLOAT_803df9b4 * fVar8 - FLOAT_803df9ac);
        if ((double)FLOAT_803df9a8 < dVar45) {
          dVar42 = 1.0 / SQRT(dVar45);
          dVar42 = DOUBLE_803df9d8 * dVar42 * -(dVar45 * dVar42 * dVar42 - DOUBLE_803df9e0);
          dVar42 = DOUBLE_803df9d8 * dVar42 * -(dVar45 * dVar42 * dVar42 - DOUBLE_803df9e0);
          dVar45 = (double)(float)(dVar45 * DOUBLE_803df9d8 * dVar42 *
                                            -(dVar45 * dVar42 * dVar42 - DOUBLE_803df9e0));
        }
      }
      *(char *)(DAT_803ddc30 +
               (uVar19 & 7) + ((int)uVar19 >> 3) * 0x20 + (uVar21 & 3) * 8 +
               ((int)uVar21 >> 2) * 0x200 + 0x60) = (char)(int)(dVar40 * dVar45);
      uVar21 = uVar21 + 1;
      iVar16 = iVar16 + -1;
    } while (iVar16 != 0);
    uVar19 = uVar19 + 1;
  } while ((int)uVar19 < 0x80);
  FUN_802420e0(DAT_803ddc30 + 0x60,*(int *)(DAT_803ddc30 + 0x44));
  DAT_803ddc14 = FUN_80054e14(4,4,3,'\0',0,0,0,1,1);
  fVar8 = FLOAT_803dfa90;
  dVar41 = DOUBLE_803dfa48;
  fVar10 = FLOAT_803dfa3c;
  fVar13 = FLOAT_803df9b8;
  fVar5 = FLOAT_803df988;
  uVar19 = 0;
  iVar16 = (int)FLOAT_803df9b8;
  iVar27 = (int)FLOAT_803dfa94;
  iVar1 = (int)FLOAT_803dfa98;
  iVar2 = (int)FLOAT_803dfa9c;
  iVar28 = 4;
  do {
    local_148 = (double)CONCAT44(0x43300000,uVar19 ^ 0x80000000);
    iVar12 = (uVar19 & 3) * 2;
    iVar6 = ((int)uVar19 >> 2) * 0x20;
    uVar11 = (ushort)(((int)(fVar5 * ((float)(local_148 - dVar41) / fVar8 - fVar13) + fVar10) &
                      0xffU) << 8);
    *(ushort *)(DAT_803ddc14 + iVar12 + iVar6 + 0x60) = uVar11 | (ushort)iVar16 & 0xff;
    *(ushort *)(DAT_803ddc14 + iVar12 + iVar6 + 0x68) = uVar11 | (ushort)iVar27 & 0xff;
    *(ushort *)(DAT_803ddc14 + iVar12 + iVar6 + 0x70) = uVar11 | (ushort)iVar1 & 0xff;
    *(ushort *)(DAT_803ddc14 + iVar12 + iVar6 + 0x78) = uVar11 | (ushort)iVar2 & 0xff;
    uVar19 = uVar19 + 1;
    iVar28 = iVar28 + -1;
  } while (iVar28 != 0);
  FUN_802420e0(DAT_803ddc14 + 0x60,*(int *)(DAT_803ddc14 + 0x44));
  iVar16 = FUN_80054e14(0x80,0x80,1,'\0',0,0,0,1,1);
  FUN_800033a8(iVar16 + 0x60,0,*(uint *)(iVar16 + 0x44));
  *(undefined2 *)(iVar16 + 0xe) = 1;
  FUN_802420e0(iVar16 + 0x60,*(int *)(iVar16 + 0x44));
  DAT_8038ee3c = iVar16;
  iVar16 = FUN_80054e14(0x80,0x80,1,'\0',0,0,0,1,1);
  FUN_800033a8(iVar16 + 0x60,0,*(uint *)(iVar16 + 0x44));
  *(undefined2 *)(iVar16 + 0xe) = 1;
  FUN_802420e0(iVar16 + 0x60,*(int *)(iVar16 + 0x44));
  DAT_8038ee40 = iVar16;
  iVar16 = FUN_80054e14(0x80,0x80,1,'\0',0,0,0,1,1);
  FUN_800033a8(iVar16 + 0x60,0,*(uint *)(iVar16 + 0x44));
  *(undefined2 *)(iVar16 + 0xe) = 1;
  FUN_802420e0(iVar16 + 0x60,*(int *)(iVar16 + 0x44));
  DAT_8038ee44 = iVar16;
  FUN_80258c48();
  iVar16 = 0;
  iVar27 = 2;
  do {
    puVar26[0x10] = 0;
    puVar26[0x11] = 1;
    puVar26[0x24] = 0;
    puVar26[0x25] = 1;
    puVar26[0x38] = 0;
    puVar26[0x39] = 1;
    puVar26[0x4c] = 0;
    puVar26[0x4d] = 1;
    puVar26[0x60] = 0;
    puVar26[0x61] = 1;
    puVar26[0x74] = 0;
    puVar26[0x75] = 1;
    puVar26[0x88] = 0;
    puVar26[0x89] = 1;
    puVar26[0x9c] = 0;
    puVar26[0x9d] = 1;
    puVar26[0xb0] = 0;
    puVar26[0xb1] = 1;
    puVar26[0xc4] = 0;
    puVar26[0xc5] = 1;
    puVar26[0xd8] = 0;
    puVar26[0xd9] = 1;
    puVar26[0xec] = 0;
    puVar26[0xed] = 1;
    puVar26[0x100] = 0;
    puVar26[0x101] = 1;
    puVar26[0x114] = 0;
    puVar26[0x115] = 1;
    puVar26[0x128] = 0;
    puVar26[0x129] = 1;
    puVar26[0x13c] = 0;
    puVar26[0x13d] = 1;
    puVar26 = puVar26 + 0x140;
    iVar16 = iVar16 + 0x10;
    iVar27 = iVar27 + -1;
  } while (iVar27 != 0);
  puVar26 = &DAT_8038eba8 + iVar16 * 0x14;
  iVar27 = 0x21 - iVar16;
  if (iVar16 < 0x21) {
    do {
      puVar26[0x10] = 0;
      puVar26[0x11] = 1;
      puVar26 = puVar26 + 0x14;
      iVar27 = iVar27 + -1;
    } while (iVar27 != 0);
  }
  FUN_8025b210();
  FUN_80022e00(uVar15 & 0xff);
  FUN_80286880();
  return;
}

