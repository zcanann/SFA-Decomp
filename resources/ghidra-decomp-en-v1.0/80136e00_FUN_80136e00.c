// Function: FUN_80136e00
// Entry: 80136e00
// Size: 1824 bytes

/* WARNING: Removing unreachable block (ram,0x801374f8) */
/* WARNING: Removing unreachable block (ram,0x801374f0) */
/* WARNING: Removing unreachable block (ram,0x80137500) */

void FUN_80136e00(void)

{
  byte bVar1;
  byte bVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  undefined4 uVar10;
  uint uVar11;
  uint uVar12;
  uint uVar13;
  undefined4 *puVar14;
  undefined4 *puVar15;
  undefined4 uVar16;
  undefined8 in_f29;
  double dVar17;
  undefined8 in_f30;
  double dVar18;
  undefined8 in_f31;
  double dVar19;
  undefined8 uVar20;
  undefined4 local_a8;
  undefined4 local_a4;
  undefined4 local_a0;
  undefined4 local_9c;
  undefined4 local_98;
  undefined4 local_94;
  undefined4 local_90;
  undefined4 local_8c;
  undefined4 local_88;
  uint uStack132;
  undefined4 local_80;
  uint uStack124;
  undefined4 local_78;
  uint uStack116;
  undefined4 local_70;
  uint uStack108;
  undefined4 local_68;
  uint uStack100;
  undefined4 local_60;
  uint uStack92;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar16 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  uVar20 = FUN_802860c8();
  uVar6 = (undefined4)((ulonglong)uVar20 >> 0x20);
  puVar14 = (undefined4 *)uVar20;
  dVar18 = DOUBLE_803e23a8;
  dVar19 = DOUBLE_803e23b0;
  do {
    bVar2 = *(byte *)puVar14;
    puVar15 = (undefined4 *)((int)puVar14 + 1);
    if (bVar2 == 0) {
      __psq_l0(auStack8,uVar16);
      __psq_l1(auStack8,uVar16);
      __psq_l0(auStack24,uVar16);
      __psq_l1(auStack24,uVar16);
      __psq_l0(auStack40,uVar16);
      __psq_l1(auStack40,uVar16);
      FUN_80286114((int)puVar15 - (int)(undefined4 *)uVar20);
      return;
    }
    uVar13 = 0;
    if (bVar2 == 0x82) {
      if (DAT_803dda0c == 0) {
        iVar3 = DAT_803dda18 + 10;
        uVar11 = (uint)DAT_803dda14;
        uVar12 = (uint)DAT_803dda16;
        uVar4 = countLeadingZeros(DAT_803dda1a - uVar12);
        uVar5 = countLeadingZeros(iVar3 - uVar11);
        if ((uVar4 | uVar5) >> 5 == 0) {
          if (1 < uVar12) {
            uVar12 = uVar12 - 2;
          }
          uVar4 = DAT_803dda1a + 2;
          local_88 = 0x43300000;
          uStack124 = (uint)DAT_803dd9e0;
          local_80 = 0x43300000;
          dVar17 = (double)(FLOAT_803dd9d8 +
                           (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803e23a8));
          uStack132 = uVar12;
          uVar7 = FUN_80285fb4((double)(float)((double)(float)((double)CONCAT44(0x43300000,uVar12) -
                                                              DOUBLE_803e23a8) * dVar17));
          local_78 = 0x43300000;
          uStack116 = uVar4;
          uVar8 = FUN_80285fb4((double)(float)((double)(float)((double)CONCAT44(0x43300000,uVar4) -
                                                              DOUBLE_803e23a8) * dVar17));
          local_70 = 0x43300000;
          uStack100 = (uint)DAT_803dd9e1;
          local_68 = 0x43300000;
          dVar17 = (double)(FLOAT_803dd9dc +
                           (float)((double)CONCAT44(0x43300000,uStack100) - DOUBLE_803e23a8));
          uStack108 = uVar11;
          uVar9 = FUN_80285fb4((double)(float)((double)(float)((double)CONCAT44(0x43300000,uVar11) -
                                                              DOUBLE_803e23a8) * dVar17));
          local_60 = 0x43300000;
          uStack92 = iVar3;
          uVar10 = FUN_80285fb4((double)(float)((double)(float)((double)CONCAT44(0x43300000,iVar3) -
                                                               DOUBLE_803e23a8) * dVar17));
          local_98 = CONCAT31(CONCAT21(CONCAT11(DAT_803dd9f3,DAT_803dd9f2),DAT_803dd9f1),
                              DAT_803dd9f0);
          local_94 = local_98;
          FUN_800753b8(uVar7,uVar9,uVar8,uVar10,&local_94);
        }
      }
      DAT_803dda16 = CONCAT11(*(byte *)((int)puVar14 + 2),*(byte *)puVar15);
      puVar15 = (undefined4 *)((int)puVar14 + 5);
      DAT_803dda14 = CONCAT11(*(byte *)(puVar14 + 1),*(byte *)((int)puVar14 + 3));
      DAT_803dda18 = DAT_803dda14;
      DAT_803dda1a = DAT_803dda16;
    }
    else if (bVar2 < 0x82) {
      if (bVar2 == 0x20) {
        uVar13 = 6;
      }
      else if (bVar2 < 0x20) {
        if (bVar2 == 10) {
          if (DAT_803dda0c == 0) {
            uVar11 = DAT_803dda18 + 10;
            uVar12 = (uint)DAT_803dda14;
            uStack92 = (uint)DAT_803dda16;
            uVar4 = countLeadingZeros(DAT_803dda1a - uStack92);
            uVar5 = countLeadingZeros(uVar11 - uVar12);
            if ((uVar4 | uVar5) >> 5 == 0) {
              if (1 < uStack92) {
                uStack92 = uStack92 - 2;
              }
              iVar3 = DAT_803dda1a + 2;
              local_60 = 0x43300000;
              uStack100 = (uint)DAT_803dd9e0;
              local_68 = 0x43300000;
              dVar17 = (double)(FLOAT_803dd9d8 +
                               (float)((double)CONCAT44(0x43300000,uStack100) - DOUBLE_803e23a8));
              uVar7 = FUN_80285fb4((double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                                    uStack92) -
                                                                  DOUBLE_803e23a8) * dVar17));
              local_70 = 0x43300000;
              uStack108 = iVar3;
              uVar8 = FUN_80285fb4((double)(float)((double)(float)((double)CONCAT44(0x43300000,iVar3
                                                                                   ) -
                                                                  DOUBLE_803e23a8) * dVar17));
              local_78 = 0x43300000;
              uStack124 = (uint)DAT_803dd9e1;
              local_80 = 0x43300000;
              dVar17 = (double)(FLOAT_803dd9dc +
                               (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803e23a8));
              uStack116 = uVar12;
              uVar9 = FUN_80285fb4((double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                                    uVar12) -
                                                                  DOUBLE_803e23a8) * dVar17));
              local_88 = 0x43300000;
              uStack132 = uVar11;
              uVar10 = FUN_80285fb4((double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                                     uVar11) -
                                                                   DOUBLE_803e23a8) * dVar17));
              local_a0 = CONCAT31(CONCAT21(CONCAT11(DAT_803dd9f3,DAT_803dd9f2),DAT_803dd9f1),
                                  DAT_803dd9f0);
              local_9c = local_a0;
              FUN_800753b8(uVar7,uVar9,uVar8,uVar10,&local_9c);
            }
          }
          DAT_803dda16 = (ushort)DAT_803dda08;
          DAT_803dda14 = DAT_803dda18 + 0xb;
          DAT_803dda18 = DAT_803dda14;
          DAT_803dda1a = DAT_803dda16;
        }
        else {
          if ((9 < bVar2) || (bVar2 < 9)) goto LAB_801372ec;
          uVar13 = (uint)DAT_803dbc10;
          iVar3 = (uint)DAT_803dda1a - (DAT_803dda1a / uVar13) * uVar13;
          if (iVar3 != 0) {
            uVar13 = uVar13 - iVar3;
          }
        }
      }
      else if (bVar2 < 0x81) {
LAB_801372ec:
        uVar13 = FUN_80136a40(uVar6,bVar2);
      }
      else {
        uVar7 = *puVar15;
        puVar15 = (undefined4 *)((int)puVar14 + 5);
        if (DAT_803dda0c != 0) {
          local_90 = uVar7;
          local_8c = uVar7;
          FUN_8025bcc4(1,&local_90);
        }
      }
    }
    else if (bVar2 == 0x86) {
      bVar1 = *(byte *)puVar15;
      puVar15 = (undefined4 *)((int)puVar14 + 3);
      DAT_803dbc10 = CONCAT11(*(byte *)((int)puVar14 + 2),bVar1);
    }
    else if (bVar2 < 0x86) {
      if (bVar2 == 0x84) {
        DAT_803dda10 = 1;
      }
      else if (bVar2 < 0x84) {
        DAT_803dda10 = 0;
      }
      else {
        bVar1 = *(byte *)puVar15;
        puVar15 = (undefined4 *)((int)puVar14 + 5);
        if (DAT_803dda0c == 0) {
          DAT_803dd9f0 = *(byte *)(puVar14 + 1);
          DAT_803dd9f1 = *(byte *)((int)puVar14 + 3);
          DAT_803dd9f2 = *(byte *)((int)puVar14 + 2);
          DAT_803dd9f3 = bVar1;
          FUN_8005d118(uVar6);
        }
      }
    }
    else {
      if (0x87 < bVar2) goto LAB_801372ec;
      DAT_803dd9e0 = *(byte *)puVar15;
      DAT_803dd9e1 = *(byte *)((int)puVar14 + 2);
      puVar15 = (undefined4 *)((int)puVar14 + 3);
    }
    if (((DAT_803dda10 != 0) && (0x1f < bVar2)) && (bVar2 < 0x80)) {
      uVar13 = 7;
    }
    uVar13 = DAT_803dda1a + uVar13 & 0xffff;
    DAT_803dda1a = (ushort)uVar13;
    local_60 = 0x43300000;
    uStack100 = (uint)DAT_803dd9e0;
    local_68 = 0x43300000;
    dVar17 = (double)(FLOAT_803dd9d8 + (float)((double)CONCAT44(0x43300000,uStack100) - dVar18));
    uStack108 = DAT_803dd9f6 - 0x10 ^ 0x80000000;
    local_70 = 0x43300000;
    puVar14 = puVar15;
    uStack92 = uVar13;
    if ((float)((double)CONCAT44(0x43300000,uStack108) - dVar19) <
        (float)((double)(float)((double)CONCAT44(0x43300000,uVar13) - dVar18) * dVar17)) {
      if (DAT_803dda0c == 0) {
        uVar11 = DAT_803dda18 + 10;
        uVar12 = (uint)DAT_803dda14;
        uStack92 = (uint)DAT_803dda16;
        uVar4 = countLeadingZeros(uVar13 - uStack92);
        uVar5 = countLeadingZeros(uVar11 - uVar12);
        if ((uVar4 | uVar5) >> 5 == 0) {
          if (1 < uStack92) {
            uStack92 = uStack92 - 2;
          }
          local_60 = 0x43300000;
          uVar7 = FUN_80285fb4((double)(float)((double)(float)((double)CONCAT44(0x43300000,uStack92)
                                                              - DOUBLE_803e23a8) * dVar17));
          local_68 = 0x43300000;
          uStack100 = uVar13 + 2;
          uVar8 = FUN_80285fb4((double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                                uVar13 + 2) -
                                                              DOUBLE_803e23a8) * dVar17));
          local_70 = 0x43300000;
          uStack116 = (uint)DAT_803dd9e1;
          local_78 = 0x43300000;
          dVar17 = (double)(FLOAT_803dd9dc +
                           (float)((double)CONCAT44(0x43300000,uStack116) - DOUBLE_803e23a8));
          uStack108 = uVar12;
          uVar9 = FUN_80285fb4((double)(float)((double)(float)((double)CONCAT44(0x43300000,uVar12) -
                                                              DOUBLE_803e23a8) * dVar17));
          local_80 = 0x43300000;
          uStack124 = uVar11;
          uVar10 = FUN_80285fb4((double)(float)((double)(float)((double)CONCAT44(0x43300000,uVar11)
                                                               - DOUBLE_803e23a8) * dVar17));
          local_a8 = CONCAT31(CONCAT21(CONCAT11(DAT_803dd9f3,DAT_803dd9f2),DAT_803dd9f1),
                              DAT_803dd9f0);
          local_a4 = local_a8;
          FUN_800753b8(uVar7,uVar9,uVar8,uVar10,&local_a4);
          uVar13 = uStack92;
        }
      }
      uStack92 = uVar13;
      DAT_803dda16 = (ushort)DAT_803dda08;
      DAT_803dda14 = DAT_803dda18 + 0xb;
      DAT_803dda18 = DAT_803dda14;
      DAT_803dda1a = DAT_803dda16;
    }
  } while( true );
}

