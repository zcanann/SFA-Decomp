// Function: FUN_800074ec
// Entry: 800074ec
// Size: 588 bytes

/* WARNING: Removing unreachable block (ram,0x80007500) */
/* WARNING: Removing unreachable block (ram,0x800074fc) */
/* WARNING: Removing unreachable block (ram,0x80007510) */

void FUN_800074ec(void)

{
  byte *in_r6;
  ushort *in_r8;
  uint *in_r12;
  ushort *puVar1;
  ushort *puVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  int unaff_r20;
  uint *puVar7;
  ushort uVar9;
  short *psVar8;
  ushort uVar10;
  int iVar11;
  uint uVar12;
  uint uVar13;
  uint uVar14;
  ushort *unaff_r31;
  ushort *puVar15;
  byte in_xer_ca;
  bool bVar16;
  double in_f4;
  undefined4 uVar17;
  uint in_stack_0000000c;
  
  puVar7 = (uint *)(unaff_r20 + (int)in_r12);
  __psq_st0(&stack0x0000000c,(int)((ulonglong)in_f4 >> 0x20),0x50005);
  uVar17 = __psq_l0(&stack0x0000000c,0x50005);
  __psq_st0(&stack0x0000000c,
            (int)((ulonglong)
                  (double)((float)(in_f4 - (double)CONCAT44(uVar17,0x3f800000)) * FLOAT_803de50c) >>
                 0x20),0x50005);
  in_stack_0000000c = in_stack_0000000c >> 0x10;
  uVar3 = (uint)*in_r6 * 3;
  uVar6 = *in_r12;
  uVar13 = *puVar7;
  iVar11 = 0;
  uVar5 = 3;
  puVar1 = (ushort *)(in_r6 + 4);
  puVar15 = unaff_r31;
  do {
    uVar10 = *puVar1;
    uVar4 = uVar10 & 0xf;
    uVar9 = uVar10 & 0xfff0;
    if ((uVar10 & 0xf) != 0) {
      iVar11 = iVar11 + uVar4;
      if (0x20 < iVar11) {
        uVar6 = iVar11 - uVar4 >> 3;
        in_r12 = (uint *)((int)in_r12 + uVar6);
        puVar7 = (uint *)((int)puVar7 + uVar6);
        uVar12 = iVar11 - uVar4 & 7;
        uVar6 = *in_r12 << uVar12;
        uVar13 = *puVar7 << uVar12;
        iVar11 = uVar12 + uVar4;
      }
      uVar14 = uVar6 >> 0x20 - uVar4;
      uVar12 = (uVar13 >> 0x20 - uVar4) - uVar14;
      uVar12 = ((int)(uVar12 * 0x40000 | uVar12 >> 0xe) >> 0x12) * in_stack_0000000c;
      in_xer_ca = (int)uVar12 < 0 && (uVar12 & 0x3fff) != 0;
      uVar9 = uVar9 + ((short)uVar14 + (short)((int)uVar12 >> 0xe)) * 4;
      uVar6 = uVar6 << uVar4;
      uVar13 = uVar13 << uVar4;
    }
    *puVar15 = uVar9;
    puVar2 = puVar1 + 1;
    puVar15[6] = 0;
    puVar15[0xc] = 0;
    if ((uVar10 & 0x10) != 0) {
      uVar10 = *puVar2;
      uVar4 = (uint)uVar10;
      if ((uVar10 & 0x10) != 0) {
        uVar9 = uVar10 & 0xffc0;
        uVar4 = uVar4 & 0xf;
        if ((uVar10 & 0xf) != 0) {
          iVar11 = iVar11 + uVar4;
          if (0x20 < iVar11) {
            uVar6 = iVar11 - uVar4 >> 3;
            in_r12 = (uint *)((int)in_r12 + uVar6);
            puVar7 = (uint *)((int)puVar7 + uVar6);
            uVar12 = iVar11 - uVar4 & 7;
            uVar6 = *in_r12 << uVar12;
            uVar13 = *puVar7 << uVar12;
            iVar11 = uVar12 + uVar4;
          }
          uVar14 = uVar6 >> 0x20 - uVar4;
          uVar12 = ((uVar13 >> 0x20 - uVar4) - uVar14) * in_stack_0000000c;
          in_xer_ca = (int)uVar12 < 0 && (uVar12 & 0x3fff) != 0;
          uVar9 = uVar9 + ((short)uVar14 + (short)((int)uVar12 >> 0xe)) * 2;
          uVar6 = uVar6 << uVar4;
          uVar13 = uVar13 << uVar4;
        }
        puVar15[6] = uVar9;
        puVar2 = puVar1 + 2;
        uVar4 = (uint)*puVar2;
        if ((uVar10 & 0x20) == 0) goto LAB_800075d4;
      }
      uVar10 = (ushort)uVar4 & 0xfff0;
      uVar4 = uVar4 & 0xf;
      if (uVar4 != 0) {
        iVar11 = iVar11 + uVar4;
        if (0x20 < iVar11) {
          uVar6 = iVar11 - uVar4 >> 3;
          in_r12 = (uint *)((int)in_r12 + uVar6);
          puVar7 = (uint *)((int)puVar7 + uVar6);
          uVar12 = iVar11 - uVar4 & 7;
          uVar6 = *in_r12 << uVar12;
          uVar13 = *puVar7 << uVar12;
          iVar11 = uVar12 + uVar4;
        }
        uVar14 = uVar6 >> 0x20 - uVar4;
        uVar12 = (uVar13 >> 0x20 - uVar4) - uVar14;
        uVar12 = ((int)(uVar12 * 0x10000 | uVar12 >> 0x10) >> 0x10) * in_stack_0000000c;
        in_xer_ca = (int)uVar12 < 0 && (uVar12 & 0x3fff) != 0;
        uVar10 = uVar10 + (short)uVar14 + (short)((int)uVar12 >> 0xe);
        uVar6 = uVar6 << uVar4;
        uVar13 = uVar13 << uVar4;
      }
      puVar15[0xc] = uVar10;
      puVar2 = puVar2 + 1;
    }
LAB_800075d4:
    bVar16 = CARRY4(uVar5,in_xer_ca - 1);
    uVar5 = uVar5 + (in_xer_ca - 1);
    if (uVar5 == 0) {
      uVar5 = 3;
      puVar15 = puVar15 + 0x1d;
    }
    puVar15 = puVar15 + 1;
    uVar4 = bVar16 - 1;
    in_xer_ca = CARRY4(uVar3,uVar4);
    uVar3 = uVar3 + uVar4;
    puVar1 = puVar2;
    if (uVar3 == 0) {
      for (; *in_r8 != 0x1000; in_r8 = in_r8 + 4) {
        psVar8 = (short *)((uint)*in_r8 + (int)unaff_r31);
        *psVar8 = *psVar8 + in_r8[2];
      }
      return;
    }
  } while( true );
}

