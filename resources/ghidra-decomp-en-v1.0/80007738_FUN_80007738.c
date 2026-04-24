// Function: FUN_80007738
// Entry: 80007738
// Size: 584 bytes

void FUN_80007738(void)

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
  uint uVar8;
  short *psVar9;
  ushort uVar10;
  int iVar11;
  uint uVar12;
  uint uVar13;
  uint uVar14;
  ushort *unaff_r31;
  ushort *puVar15;
  byte in_xer_ca;
  bool bVar16;
  
  puVar7 = (uint *)(unaff_r20 + (int)in_r12);
  uVar3 = (uint)*in_r6 * 3;
  uVar6 = *in_r12;
  uVar12 = *puVar7;
  iVar11 = 0;
  uVar5 = 3;
  puVar1 = (ushort *)(in_r6 + 4);
  puVar15 = unaff_r31;
  do {
    uVar10 = *puVar1;
    uVar8 = (uint)uVar10;
    uVar4 = uVar8 & 0xf;
    if ((uVar10 & 0xf) == 0) {
      *puVar15 = uVar10;
      puVar15[3] = uVar10;
    }
    else {
      uVar8 = uVar8 & 0xfff0;
      iVar11 = iVar11 + uVar4;
      if (0x20 < iVar11) {
        uVar6 = iVar11 - uVar4 >> 3;
        in_r12 = (uint *)((int)in_r12 + uVar6);
        puVar7 = (uint *)((int)puVar7 + uVar6);
        uVar14 = iVar11 - uVar4 & 7;
        uVar6 = *in_r12 << uVar14;
        uVar12 = *puVar7 << uVar14;
        iVar11 = uVar14 + uVar4;
      }
      uVar13 = uVar6 >> 0x20 - uVar4;
      uVar14 = uVar12 >> 0x20 - uVar4;
      uVar6 = uVar6 << uVar4;
      uVar12 = uVar12 << uVar4;
      *puVar15 = (short)(uVar13 << 2) + (short)uVar8;
      puVar15[3] = (short)(uVar14 << 2) + (short)uVar8;
    }
    puVar2 = puVar1 + 1;
    puVar15[6] = 0;
    puVar15[9] = 0;
    puVar15[0xc] = 0;
    puVar15[0xf] = 0;
    if ((uVar8 & 0x10) != 0) {
      uVar10 = *puVar2;
      uVar4 = (uint)uVar10;
      if ((uVar10 & 0x10) != 0) {
        uVar4 = uVar4 & 0xf;
        if ((uVar10 & 0xf) == 0) {
          puVar15[6] = uVar10;
          puVar15[9] = uVar10;
        }
        else {
          iVar11 = iVar11 + uVar4;
          if (0x20 < iVar11) {
            uVar6 = iVar11 - uVar4 >> 3;
            in_r12 = (uint *)((int)in_r12 + uVar6);
            puVar7 = (uint *)((int)puVar7 + uVar6);
            uVar8 = iVar11 - uVar4 & 7;
            uVar6 = *in_r12 << uVar8;
            uVar12 = *puVar7 << uVar8;
            iVar11 = uVar8 + uVar4;
          }
          uVar14 = uVar6 >> 0x20 - uVar4;
          uVar8 = uVar12 >> 0x20 - uVar4;
          uVar6 = uVar6 << uVar4;
          uVar12 = uVar12 << uVar4;
          puVar15[6] = (short)(uVar14 << 1) + (uVar10 & 0xffc0);
          puVar15[9] = (short)(uVar8 << 1) + (uVar10 & 0xffc0);
        }
        puVar2 = puVar1 + 2;
        uVar4 = (uint)*puVar2;
        if ((uVar10 & 0x20) == 0) goto LAB_80007808;
      }
      uVar8 = uVar4 & 0xf;
      uVar10 = (ushort)uVar4;
      if (uVar8 == 0) {
        puVar15[0xc] = uVar10;
        puVar15[0xf] = uVar10;
      }
      else {
        iVar11 = iVar11 + uVar8;
        if (0x20 < iVar11) {
          uVar6 = iVar11 - uVar8 >> 3;
          in_r12 = (uint *)((int)in_r12 + uVar6);
          puVar7 = (uint *)((int)puVar7 + uVar6);
          uVar4 = iVar11 - uVar8 & 7;
          uVar6 = *in_r12 << uVar4;
          uVar12 = *puVar7 << uVar4;
          iVar11 = uVar4 + uVar8;
        }
        uVar14 = uVar6 >> 0x20 - uVar8;
        uVar4 = uVar12 >> 0x20 - uVar8;
        uVar6 = uVar6 << uVar8;
        uVar12 = uVar12 << uVar8;
        puVar15[0xc] = (short)uVar14 + (uVar10 & 0xfff0);
        puVar15[0xf] = (short)uVar4 + (uVar10 & 0xfff0);
      }
      puVar2 = puVar2 + 1;
    }
LAB_80007808:
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
        psVar9 = (short *)((uint)*in_r8 + (int)unaff_r31);
        uVar10 = in_r8[2];
        *psVar9 = *psVar9 + uVar10;
        psVar9[3] = psVar9[3] + uVar10;
      }
      return;
    }
  } while( true );
}

