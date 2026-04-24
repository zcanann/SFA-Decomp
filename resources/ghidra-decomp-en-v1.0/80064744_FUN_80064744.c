// Function: FUN_80064744
// Entry: 80064744
// Size: 1352 bytes

/* WARNING: Removing unreachable block (ram,0x80064758) */
/* WARNING: Removing unreachable block (ram,0x80064c6c) */

void FUN_80064744(void)

{
  byte bVar1;
  byte bVar2;
  int iVar3;
  undefined2 uVar7;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  undefined *puVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  short sVar12;
  ushort uVar13;
  short sVar14;
  short *psVar15;
  ushort uVar16;
  int iVar17;
  short *psVar18;
  undefined4 uVar19;
  undefined8 in_f31;
  double dVar20;
  short asStack6872 [3400];
  undefined4 local_48;
  uint uStack68;
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  undefined4 uStack8;
  undefined4 uStack4;
  
  uVar19 = 0;
  uStack4 = (undefined4)in_f31;
  uStack8 = (undefined4)((ulonglong)in_f31 >> 0x20);
  iVar3 = FUN_802860d0();
  DAT_803dcf4e = 1;
  DAT_803dcf5e = 0;
  DAT_803dcf5c = 0;
  bVar1 = *(byte *)(iVar3 + 0x5c);
  psVar18 = *(short **)(iVar3 + 0x30);
  for (iVar17 = 0; uVar7 = (undefined2)((uint)uVar19 >> 0x10), iVar17 < (int)(uint)bVar1;
      iVar17 = iVar17 + 1) {
    if (DAT_803dcf5e < 0x5dc) {
      puVar8 = (undefined *)(DAT_803dcf34 + DAT_803dcf5e * 0x10);
      *puVar8 = *(undefined *)(psVar18 + 6);
      puVar8[1] = *(undefined *)((int)psVar18 + 0xd);
      puVar8[3] = *(undefined *)((int)psVar18 + 0xf);
      if ((puVar8[3] & 0x3f) == 0x11) {
        puVar8[3] = puVar8[3] & 0xc0;
        puVar8[3] = puVar8[3] | 2;
      }
      puVar8[2] = *(undefined *)(psVar18 + 7);
      puVar8[2] = puVar8[2] ^ 0x10;
      *(short *)(puVar8 + 0xc) = psVar18[8];
      iVar9 = 0;
      psVar15 = psVar18;
      dVar20 = DOUBLE_803decd8;
      do {
        uStack68 = (int)*psVar15 ^ 0x80000000;
        local_48 = 0x43300000;
        uStack60 = (int)psVar15[2] ^ 0x80000000;
        local_40 = 0x43300000;
        uStack52 = (int)psVar15[4] ^ 0x80000000;
        local_38 = 0x43300000;
        if (DAT_803dcf5c < 0x6a4) {
          uVar7 = FUN_80063ff0((double)(float)((double)CONCAT44(0x43300000,uStack68) - dVar20),
                               (double)(float)((double)CONCAT44(0x43300000,uStack60) - dVar20),
                               (double)(float)((double)CONCAT44(0x43300000,uStack52) - dVar20),
                               (int)DAT_803dcf5e,asStack6872);
          *(undefined2 *)(puVar8 + 4) = uVar7;
        }
        psVar15 = psVar15 + 1;
        puVar8 = puVar8 + 2;
        iVar9 = iVar9 + 1;
      } while (iVar9 < 2);
      DAT_803dcf5e = DAT_803dcf5e + 1;
    }
    psVar18 = psVar18 + 10;
  }
  iVar17 = 0;
  for (iVar9 = 0; iVar9 < DAT_803dcf5e; iVar9 = iVar9 + 1) {
    iVar6 = DAT_803dcf34 + iVar17;
    sVar14 = asStack6872[*(short *)(iVar6 + 4) * 2];
    if ((sVar14 < 0) || (sVar14 == iVar9)) {
      sVar14 = asStack6872[*(short *)(iVar6 + 4) * 2 + 1];
      if ((sVar14 < 0) || (sVar14 == iVar9)) {
        *(undefined2 *)(iVar6 + 8) = 0xffff;
      }
      else {
        *(short *)(iVar6 + 8) = sVar14;
      }
    }
    else {
      *(short *)(iVar6 + 8) = sVar14;
    }
    sVar14 = asStack6872[*(short *)(iVar6 + 6) * 2];
    if ((sVar14 < 0) || (sVar14 == iVar9)) {
      sVar14 = asStack6872[*(short *)(iVar6 + 6) * 2 + 1];
      if ((sVar14 < 0) || (sVar14 == iVar9)) {
        *(undefined2 *)(iVar6 + 10) = 0xffff;
      }
      else {
        *(short *)(iVar6 + 10) = sVar14;
      }
    }
    else {
      *(short *)(iVar6 + 10) = sVar14;
    }
    iVar17 = iVar17 + 0x10;
  }
  iVar17 = DAT_803dcf5e * 0x10 + DAT_803dcf5c * 0xc + 0x28;
  if (iVar17 != 0) {
    uVar4 = FUN_80023cc8(iVar17,0xffff00ff,0);
    *(undefined4 *)(iVar3 + 0x34) = uVar4;
    *(int *)(iVar3 + 0x3c) = *(int *)(iVar3 + 0x34) + DAT_803dcf5e * 0x10;
    *(int *)(iVar3 + 0x38) = *(int *)(iVar3 + 0x3c) + DAT_803dcf5c * 0xc;
    iVar17 = 0;
    iVar9 = 5;
    do {
      *(undefined *)(*(int *)(iVar3 + 0x38) + iVar17) = 0xff;
      *(undefined *)(*(int *)(iVar3 + 0x38) + iVar17 + 1) = 0xff;
      *(undefined *)(*(int *)(iVar3 + 0x38) + iVar17 + 2) = 0xff;
      *(undefined *)(*(int *)(iVar3 + 0x38) + iVar17 + 3) = 0xff;
      *(undefined *)(*(int *)(iVar3 + 0x38) + iVar17 + 4) = 0xff;
      *(undefined *)(*(int *)(iVar3 + 0x38) + iVar17 + 5) = 0xff;
      *(undefined *)(*(int *)(iVar3 + 0x38) + iVar17 + 6) = 0xff;
      *(undefined *)(*(int *)(iVar3 + 0x38) + iVar17 + 7) = 0xff;
      iVar17 = iVar17 + 8;
      iVar9 = iVar9 + -1;
    } while (iVar9 != 0);
    uVar16 = 0xffff;
    iVar17 = 0;
    iVar9 = 0;
    while( true ) {
      uVar7 = (undefined2)((uint)uVar19 >> 0x10);
      iVar6 = (int)DAT_803dcf5e;
      if (iVar6 <= iVar17) break;
      sVar14 = 0;
      sVar12 = 0;
      iVar10 = DAT_803dcf34;
      if (0 < iVar6) {
        do {
          if ((*(byte *)(iVar10 + 3) & 0x3f) < (*(byte *)(DAT_803dcf34 + sVar14 * 0x10 + 3) & 0x3f))
          {
            sVar14 = sVar12;
          }
          iVar10 = iVar10 + 0x10;
          sVar12 = sVar12 + 1;
          iVar6 = iVar6 + -1;
        } while (iVar6 != 0);
      }
      iVar6 = sVar14 * 0x10;
      uVar13 = (short)*(char *)(DAT_803dcf34 + iVar6 + 3) & 0x3f;
      if (0x13 < uVar13) {
        uVar13 = 1;
        FUN_801378a8(s_trackIntersect__FUNC_OVERFLOW__d_8030e87c,1);
      }
      iVar10 = (int)(short)uVar16;
      if ((short)uVar13 != iVar10) {
        *(char *)(*(int *)(iVar3 + 0x38) + (short)uVar13 * 2) = (char)iVar17;
        uVar16 = uVar13;
        if (iVar10 != -1) {
          *(char *)(*(int *)(iVar3 + 0x38) + iVar10 * 2 + 1) = (char)iVar17;
        }
      }
      iVar11 = 0;
      uVar7 = (undefined2)iVar17;
      iVar10 = iVar17;
      if (0 < iVar17) {
        do {
          if (sVar14 == *(short *)(*(int *)(iVar3 + 0x34) + iVar11 + 8)) {
            *(undefined2 *)(*(int *)(iVar3 + 0x34) + iVar11 + 8) = uVar7;
          }
          if (sVar14 == *(short *)(*(int *)(iVar3 + 0x34) + iVar11 + 10)) {
            *(undefined2 *)(*(int *)(iVar3 + 0x34) + iVar11 + 10) = uVar7;
          }
          iVar11 = iVar11 + 0x10;
          iVar10 = iVar10 + -1;
        } while (iVar10 != 0);
      }
      iVar10 = 0;
      for (iVar11 = 0; iVar11 < DAT_803dcf5e; iVar11 = iVar11 + 1) {
        iVar5 = DAT_803dcf34 + iVar10;
        if (*(char *)(iVar5 + 3) != '\x14') {
          if (sVar14 == *(short *)(iVar5 + 8)) {
            *(undefined2 *)(iVar5 + 8) = uVar7;
          }
          if (sVar14 == *(short *)(DAT_803dcf34 + iVar10 + 10)) {
            *(undefined2 *)(DAT_803dcf34 + iVar10 + 10) = uVar7;
          }
        }
        iVar10 = iVar10 + 0x10;
      }
      FUN_80003494(*(int *)(iVar3 + 0x34) + iVar9,DAT_803dcf34 + iVar6,0x10);
      *(undefined *)(DAT_803dcf34 + iVar6 + 3) = 0x14;
      iVar9 = iVar9 + 0x10;
      iVar17 = iVar17 + 1;
    }
    if ((short)uVar16 != -1) {
      *(char *)(*(int *)(iVar3 + 0x38) + (short)uVar16 * 2 + 1) = (char)DAT_803dcf5e;
    }
    FUN_80003494(*(undefined4 *)(iVar3 + 0x3c),DAT_803dcf38,DAT_803dcf5c * 0xc);
    DAT_803dcf5e = 0;
    DAT_803dcf5c = 0;
  }
  bVar1 = (byte)uVar7 & 7;
  bVar2 = (byte)((ushort)uVar7 >> 8) & 0x3f;
  if (bVar1 == 4 || bVar1 == 6) {
    dequantize(&uStack8,bVar1,bVar2);
    dequantize((int)&uStack8 + 1,bVar1,bVar2);
  }
  else if (bVar1 == 5 || bVar1 == 7) {
    dequantize(&uStack8,bVar1,bVar2);
    dequantize((int)&uStack8 + 2,bVar1,bVar2);
  }
  FUN_8028611c();
  return;
}

