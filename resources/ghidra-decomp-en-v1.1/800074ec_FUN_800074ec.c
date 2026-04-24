// Function: FUN_800074ec
// Entry: 800074ec
// Size: 588 bytes

/* WARNING: Removing unreachable block (ram,0x80007510) */
/* WARNING: Removing unreachable block (ram,0x80007500) */
/* WARNING: Removing unreachable block (ram,0x800074fc) */

void FUN_800074ec(undefined param_1,undefined param_2,undefined param_3,undefined param_4,
                 undefined param_5,undefined param_6,undefined param_7,undefined param_8,
                 undefined param_9,float param_10)

{
  longlong lVar1;
  byte bVar2;
  byte bVar3;
  double dVar4;
  float fVar5;
  undefined3 in_register_00000018;
  undefined3 in_register_00000020;
  ushort *puVar6;
  uint *in_r12;
  ushort *puVar7;
  ushort *puVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  int unaff_r20;
  uint *puVar13;
  ushort uVar15;
  short *psVar14;
  ushort uVar16;
  int iVar17;
  uint uVar18;
  uint uVar19;
  uint uVar20;
  uint uVar21;
  ushort *unaff_r31;
  ushort *puVar22;
  byte in_xer_ca;
  bool bVar23;
  uint unaff_GQR3;
  double in_f4;
  double dVar24;
  
  puVar6 = (ushort *)CONCAT31(in_register_00000020,param_6);
  puVar13 = (uint *)(unaff_r20 + (int)in_r12);
  bVar2 = (byte)unaff_GQR3 & 7;
  bVar3 = (byte)(unaff_GQR3 >> 8);
  if ((unaff_GQR3 & 0x3f00) == 0) {
    dVar24 = 1.0;
  }
  else {
    dVar24 = (double)ldexpf(bVar3 & 0x3f);
  }
  if (bVar2 == 4 || bVar2 == 6) {
    param_10 = (float)CONCAT13((char)(dVar24 * in_f4),param_10._1_3_);
  }
  else if (bVar2 == 5 || bVar2 == 7) {
    param_10 = (float)CONCAT22((short)(dVar24 * in_f4),param_10._2_2_);
  }
  else {
    param_10 = (float)in_f4;
  }
  bVar2 = (byte)(unaff_GQR3 >> 0x10) & 7;
  if ((unaff_GQR3 & 0x3f000000) == 0) {
    lVar1 = 0x3ff0000000000000;
  }
  else {
    lVar1 = ldexpf(-((byte)(unaff_GQR3 >> 0x18) & 0x3f));
  }
  if (bVar2 == 4 || bVar2 == 6) {
    dVar24 = (double)(lVar1 * (longlong)(double)param_10._0_1_);
  }
  else if (bVar2 == 5 || bVar2 == 7) {
    dVar24 = (double)(lVar1 * (longlong)(double)(short)param_10._0_2_);
  }
  else {
    dVar24 = (double)param_10;
  }
  fVar5 = (float)(in_f4 - dVar24) * FLOAT_803df18c;
  dVar24 = (double)fVar5;
  bVar2 = (byte)unaff_GQR3 & 7;
  if ((unaff_GQR3 & 0x3f00) == 0) {
    dVar4 = 1.0;
  }
  else {
    dVar4 = (double)ldexpf(bVar3 & 0x3f);
  }
  if (bVar2 == 4 || bVar2 == 6) {
    param_10 = (float)CONCAT13((char)(dVar4 * dVar24),param_10._1_3_);
  }
  else if (bVar2 == 5 || bVar2 == 7) {
    param_10._0_2_ = (ushort)(dVar4 * dVar24);
  }
  else {
    param_10._0_2_ = (ushort)((uint)fVar5 >> 0x10);
  }
  uVar20 = (uint)param_10._0_2_;
  uVar9 = (uint)*(byte *)CONCAT31(in_register_00000018,param_4) * 3;
  uVar12 = *in_r12;
  uVar19 = *puVar13;
  iVar17 = 0;
  uVar11 = 3;
  puVar7 = (ushort *)((byte *)CONCAT31(in_register_00000018,param_4) + 4);
  puVar22 = unaff_r31;
  do {
    uVar16 = *puVar7;
    uVar10 = uVar16 & 0xf;
    uVar15 = uVar16 & 0xfff0;
    if ((uVar16 & 0xf) != 0) {
      iVar17 = iVar17 + uVar10;
      if (0x20 < iVar17) {
        uVar12 = iVar17 - uVar10 >> 3;
        in_r12 = (uint *)((int)in_r12 + uVar12);
        puVar13 = (uint *)((int)puVar13 + uVar12);
        uVar18 = iVar17 - uVar10 & 7;
        uVar12 = *in_r12 << uVar18;
        uVar19 = *puVar13 << uVar18;
        iVar17 = uVar18 + uVar10;
      }
      uVar21 = uVar12 >> 0x20 - uVar10;
      uVar18 = (uVar19 >> 0x20 - uVar10) - uVar21;
      uVar18 = ((int)(uVar18 * 0x40000 | uVar18 >> 0xe) >> 0x12) * uVar20;
      in_xer_ca = (int)uVar18 < 0 && (uVar18 & 0x3fff) != 0;
      uVar15 = uVar15 + (short)(uVar21 + ((int)uVar18 >> 0xe)) * 4;
      uVar12 = uVar12 << uVar10;
      uVar19 = uVar19 << uVar10;
    }
    *puVar22 = uVar15;
    puVar8 = puVar7 + 1;
    puVar22[6] = 0;
    puVar22[0xc] = 0;
    if ((uVar16 & 0x10) != 0) {
      uVar16 = *puVar8;
      uVar10 = (uint)uVar16;
      if ((uVar16 & 0x10) != 0) {
        uVar15 = uVar16 & 0xffc0;
        uVar10 = uVar10 & 0xf;
        if ((uVar16 & 0xf) != 0) {
          iVar17 = iVar17 + uVar10;
          if (0x20 < iVar17) {
            uVar12 = iVar17 - uVar10 >> 3;
            in_r12 = (uint *)((int)in_r12 + uVar12);
            puVar13 = (uint *)((int)puVar13 + uVar12);
            uVar18 = iVar17 - uVar10 & 7;
            uVar12 = *in_r12 << uVar18;
            uVar19 = *puVar13 << uVar18;
            iVar17 = uVar18 + uVar10;
          }
          uVar21 = uVar12 >> 0x20 - uVar10;
          uVar18 = ((uVar19 >> 0x20 - uVar10) - uVar21) * uVar20;
          in_xer_ca = (int)uVar18 < 0 && (uVar18 & 0x3fff) != 0;
          uVar15 = uVar15 + ((short)uVar21 + (short)((int)uVar18 >> 0xe)) * 2;
          uVar12 = uVar12 << uVar10;
          uVar19 = uVar19 << uVar10;
        }
        puVar22[6] = uVar15;
        puVar8 = puVar7 + 2;
        uVar10 = (uint)*puVar8;
        if ((uVar16 & 0x20) == 0) goto LAB_800075d4;
      }
      uVar16 = (ushort)uVar10 & 0xfff0;
      uVar10 = uVar10 & 0xf;
      if (uVar10 != 0) {
        iVar17 = iVar17 + uVar10;
        if (0x20 < iVar17) {
          uVar12 = iVar17 - uVar10 >> 3;
          in_r12 = (uint *)((int)in_r12 + uVar12);
          puVar13 = (uint *)((int)puVar13 + uVar12);
          uVar18 = iVar17 - uVar10 & 7;
          uVar12 = *in_r12 << uVar18;
          uVar19 = *puVar13 << uVar18;
          iVar17 = uVar18 + uVar10;
        }
        uVar21 = uVar12 >> 0x20 - uVar10;
        uVar18 = (uVar19 >> 0x20 - uVar10) - uVar21;
        uVar18 = ((int)(uVar18 * 0x10000 | uVar18 >> 0x10) >> 0x10) * uVar20;
        in_xer_ca = (int)uVar18 < 0 && (uVar18 & 0x3fff) != 0;
        uVar16 = uVar16 + (short)uVar21 + (short)((int)uVar18 >> 0xe);
        uVar12 = uVar12 << uVar10;
        uVar19 = uVar19 << uVar10;
      }
      puVar22[0xc] = uVar16;
      puVar8 = puVar8 + 1;
    }
LAB_800075d4:
    bVar23 = CARRY4(uVar11,in_xer_ca - 1);
    uVar11 = uVar11 + (in_xer_ca - 1);
    if (uVar11 == 0) {
      uVar11 = 3;
      puVar22 = puVar22 + 0x1d;
    }
    puVar22 = puVar22 + 1;
    uVar10 = bVar23 - 1;
    in_xer_ca = CARRY4(uVar9,uVar10);
    uVar9 = uVar9 + uVar10;
    puVar7 = puVar8;
    if (uVar9 == 0) {
      for (; *puVar6 != 0x1000; puVar6 = puVar6 + 4) {
        psVar14 = (short *)((uint)*puVar6 + (int)unaff_r31);
        *psVar14 = *psVar14 + puVar6[2];
      }
      return;
    }
  } while( true );
}

