// Function: FUN_80007738
// Entry: 80007738
// Size: 584 bytes

void FUN_80007738(undefined param_1,undefined param_2,undefined param_3,undefined param_4,
                 undefined param_5,undefined param_6,undefined param_7,undefined param_8,
                 undefined param_9,undefined4 param_10)

{
  undefined3 in_register_00000018;
  undefined3 in_register_00000020;
  ushort *puVar1;
  uint *in_r12;
  ushort *puVar2;
  ushort *puVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  int unaff_r20;
  uint *puVar8;
  uint uVar9;
  short *psVar10;
  ushort uVar11;
  int iVar12;
  uint uVar13;
  uint uVar14;
  uint uVar15;
  ushort *unaff_r31;
  ushort *puVar16;
  byte in_xer_ca;
  bool bVar17;
  
  puVar1 = (ushort *)CONCAT31(in_register_00000020,param_6);
  puVar8 = (uint *)(unaff_r20 + (int)in_r12);
  uVar4 = (uint)*(byte *)CONCAT31(in_register_00000018,param_4) * 3;
  uVar7 = *in_r12;
  uVar13 = *puVar8;
  iVar12 = 0;
  uVar6 = 3;
  puVar2 = (ushort *)((byte *)CONCAT31(in_register_00000018,param_4) + 4);
  puVar16 = unaff_r31;
  do {
    uVar11 = *puVar2;
    uVar9 = (uint)uVar11;
    uVar5 = uVar9 & 0xf;
    if ((uVar11 & 0xf) == 0) {
      *puVar16 = uVar11;
      puVar16[3] = uVar11;
    }
    else {
      uVar9 = uVar9 & 0xfff0;
      iVar12 = iVar12 + uVar5;
      if (0x20 < iVar12) {
        uVar7 = iVar12 - uVar5 >> 3;
        in_r12 = (uint *)((int)in_r12 + uVar7);
        puVar8 = (uint *)((int)puVar8 + uVar7);
        uVar15 = iVar12 - uVar5 & 7;
        uVar7 = *in_r12 << uVar15;
        uVar13 = *puVar8 << uVar15;
        iVar12 = uVar15 + uVar5;
      }
      uVar14 = uVar7 >> 0x20 - uVar5;
      uVar15 = uVar13 >> 0x20 - uVar5;
      uVar7 = uVar7 << uVar5;
      uVar13 = uVar13 << uVar5;
      *puVar16 = (short)(uVar14 << 2) + (short)uVar9;
      puVar16[3] = (short)(uVar15 << 2) + (short)uVar9;
    }
    puVar3 = puVar2 + 1;
    puVar16[6] = 0;
    puVar16[9] = 0;
    puVar16[0xc] = 0;
    puVar16[0xf] = 0;
    if ((uVar9 & 0x10) != 0) {
      uVar11 = *puVar3;
      uVar5 = (uint)uVar11;
      if ((uVar11 & 0x10) != 0) {
        uVar5 = uVar5 & 0xf;
        if ((uVar11 & 0xf) == 0) {
          puVar16[6] = uVar11;
          puVar16[9] = uVar11;
        }
        else {
          iVar12 = iVar12 + uVar5;
          if (0x20 < iVar12) {
            uVar7 = iVar12 - uVar5 >> 3;
            in_r12 = (uint *)((int)in_r12 + uVar7);
            puVar8 = (uint *)((int)puVar8 + uVar7);
            uVar9 = iVar12 - uVar5 & 7;
            uVar7 = *in_r12 << uVar9;
            uVar13 = *puVar8 << uVar9;
            iVar12 = uVar9 + uVar5;
          }
          uVar15 = uVar7 >> 0x20 - uVar5;
          uVar9 = uVar13 >> 0x20 - uVar5;
          uVar7 = uVar7 << uVar5;
          uVar13 = uVar13 << uVar5;
          puVar16[6] = (short)(uVar15 << 1) + (uVar11 & 0xffc0);
          puVar16[9] = (short)(uVar9 << 1) + (uVar11 & 0xffc0);
        }
        puVar3 = puVar2 + 2;
        uVar5 = (uint)*puVar3;
        if ((uVar11 & 0x20) == 0) goto LAB_80007808;
      }
      uVar9 = uVar5 & 0xf;
      uVar11 = (ushort)uVar5;
      if (uVar9 == 0) {
        puVar16[0xc] = uVar11;
        puVar16[0xf] = uVar11;
      }
      else {
        iVar12 = iVar12 + uVar9;
        if (0x20 < iVar12) {
          uVar7 = iVar12 - uVar9 >> 3;
          in_r12 = (uint *)((int)in_r12 + uVar7);
          puVar8 = (uint *)((int)puVar8 + uVar7);
          uVar5 = iVar12 - uVar9 & 7;
          uVar7 = *in_r12 << uVar5;
          uVar13 = *puVar8 << uVar5;
          iVar12 = uVar5 + uVar9;
        }
        uVar15 = uVar7 >> 0x20 - uVar9;
        uVar5 = uVar13 >> 0x20 - uVar9;
        uVar7 = uVar7 << uVar9;
        uVar13 = uVar13 << uVar9;
        puVar16[0xc] = (short)uVar15 + (uVar11 & 0xfff0);
        puVar16[0xf] = (short)uVar5 + (uVar11 & 0xfff0);
      }
      puVar3 = puVar3 + 1;
    }
LAB_80007808:
    bVar17 = CARRY4(uVar6,in_xer_ca - 1);
    uVar6 = uVar6 + (in_xer_ca - 1);
    if (uVar6 == 0) {
      uVar6 = 3;
      puVar16 = puVar16 + 0x1d;
    }
    puVar16 = puVar16 + 1;
    uVar5 = bVar17 - 1;
    in_xer_ca = CARRY4(uVar4,uVar5);
    uVar4 = uVar4 + uVar5;
    puVar2 = puVar3;
    if (uVar4 == 0) {
      for (; *puVar1 != 0x1000; puVar1 = puVar1 + 4) {
        psVar10 = (short *)((uint)*puVar1 + (int)unaff_r31);
        uVar11 = puVar1[2];
        *psVar10 = *psVar10 + uVar11;
        psVar10[3] = psVar10[3] + uVar11;
      }
      return;
    }
  } while( true );
}

