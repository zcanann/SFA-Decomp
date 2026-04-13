// Function: FUN_80137188
// Entry: 80137188
// Size: 1824 bytes

/* WARNING: Removing unreachable block (ram,0x80137888) */
/* WARNING: Removing unreachable block (ram,0x80137880) */
/* WARNING: Removing unreachable block (ram,0x80137878) */
/* WARNING: Removing unreachable block (ram,0x801371a8) */
/* WARNING: Removing unreachable block (ram,0x801371a0) */
/* WARNING: Removing unreachable block (ram,0x80137198) */

void FUN_80137188(void)

{
  byte bVar1;
  undefined4 uVar2;
  uint uVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  uint uVar13;
  byte *pbVar14;
  byte *pbVar15;
  double in_f29;
  double dVar16;
  double in_f30;
  double dVar17;
  double in_f31;
  double dVar18;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar19;
  undefined4 local_a8;
  undefined4 local_a4;
  undefined4 local_a0;
  undefined4 local_9c;
  undefined4 local_98;
  undefined4 local_94;
  undefined4 local_90;
  undefined4 local_8c;
  undefined4 local_88;
  uint uStack_84;
  undefined4 local_80;
  uint uStack_7c;
  undefined4 local_78;
  uint uStack_74;
  undefined4 local_70;
  uint uStack_6c;
  undefined4 local_68;
  uint uStack_64;
  undefined4 local_60;
  uint uStack_5c;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  uVar19 = FUN_8028682c();
  uVar4 = (undefined4)((ulonglong)uVar19 >> 0x20);
  pbVar14 = (byte *)uVar19;
  dVar17 = DOUBLE_803e3038;
  dVar18 = DOUBLE_803e3040;
  do {
    uVar13 = (uint)*pbVar14;
    pbVar15 = pbVar14 + 1;
    if (uVar13 == 0) {
      FUN_80286878();
      return;
    }
    uVar12 = 0;
    if (uVar13 == 0x82) {
      if (DAT_803de68c == 0) {
        iVar5 = DAT_803de698 + 10;
        uVar11 = (uint)DAT_803de694;
        uVar10 = (uint)DAT_803de696;
        uVar3 = countLeadingZeros(DAT_803de69a - uVar10);
        uVar9 = countLeadingZeros(iVar5 - uVar11);
        if (uVar3 >> 5 == 0 && uVar9 >> 5 == 0) {
          if (1 < uVar10) {
            uVar10 = uVar10 - 2;
          }
          uVar3 = DAT_803de69a + 2;
          local_88 = 0x43300000;
          uStack_7c = (uint)DAT_803de660;
          local_80 = 0x43300000;
          dVar16 = (double)(FLOAT_803de658 +
                           (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e3038));
          uStack_84 = uVar10;
          iVar6 = FUN_80286718((double)(float)((double)(float)((double)CONCAT44(0x43300000,uVar10) -
                                                              DOUBLE_803e3038) * dVar16));
          local_78 = 0x43300000;
          uStack_74 = uVar3;
          iVar7 = FUN_80286718((double)(float)((double)(float)((double)CONCAT44(0x43300000,uVar3) -
                                                              DOUBLE_803e3038) * dVar16));
          local_70 = 0x43300000;
          uStack_64 = (uint)DAT_803de661;
          local_68 = 0x43300000;
          dVar16 = (double)(FLOAT_803de65c +
                           (float)((double)CONCAT44(0x43300000,uStack_64) - DOUBLE_803e3038));
          uStack_6c = uVar11;
          iVar8 = FUN_80286718((double)(float)((double)(float)((double)CONCAT44(0x43300000,uVar11) -
                                                              DOUBLE_803e3038) * dVar16));
          local_60 = 0x43300000;
          uStack_5c = iVar5;
          iVar5 = FUN_80286718((double)(float)((double)(float)((double)CONCAT44(0x43300000,iVar5) -
                                                              DOUBLE_803e3038) * dVar16));
          local_98 = CONCAT31(CONCAT21(CONCAT11(DAT_803de673,DAT_803de672),DAT_803de671),
                              DAT_803de670);
          local_94 = local_98;
          FUN_80075534(iVar6,iVar8,iVar7,iVar5,&local_94);
        }
      }
      DAT_803de696 = CONCAT11(pbVar14[2],*pbVar15);
      pbVar15 = pbVar14 + 5;
      DAT_803de694 = CONCAT11(pbVar14[4],pbVar14[3]);
      DAT_803de698 = DAT_803de694;
      DAT_803de69a = DAT_803de696;
    }
    else if (uVar13 < 0x82) {
      if (uVar13 == 0x20) {
        uVar12 = 6;
      }
      else if (uVar13 < 0x20) {
        if (uVar13 == 10) {
          if (DAT_803de68c == 0) {
            uVar11 = DAT_803de698 + 10;
            uVar10 = (uint)DAT_803de694;
            uStack_5c = (uint)DAT_803de696;
            uVar3 = countLeadingZeros(DAT_803de69a - uStack_5c);
            uVar9 = countLeadingZeros(uVar11 - uVar10);
            if (uVar3 >> 5 == 0 && uVar9 >> 5 == 0) {
              if (1 < uStack_5c) {
                uStack_5c = uStack_5c - 2;
              }
              iVar6 = DAT_803de69a + 2;
              local_60 = 0x43300000;
              uStack_64 = (uint)DAT_803de660;
              local_68 = 0x43300000;
              dVar16 = (double)(FLOAT_803de658 +
                               (float)((double)CONCAT44(0x43300000,uStack_64) - DOUBLE_803e3038));
              iVar5 = FUN_80286718((double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                                    uStack_5c) -
                                                                  DOUBLE_803e3038) * dVar16));
              local_70 = 0x43300000;
              uStack_6c = iVar6;
              iVar6 = FUN_80286718((double)(float)((double)(float)((double)CONCAT44(0x43300000,iVar6
                                                                                   ) -
                                                                  DOUBLE_803e3038) * dVar16));
              local_78 = 0x43300000;
              uStack_7c = (uint)DAT_803de661;
              local_80 = 0x43300000;
              dVar16 = (double)(FLOAT_803de65c +
                               (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e3038));
              uStack_74 = uVar10;
              iVar7 = FUN_80286718((double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                                    uVar10) -
                                                                  DOUBLE_803e3038) * dVar16));
              local_88 = 0x43300000;
              uStack_84 = uVar11;
              iVar8 = FUN_80286718((double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                                    uVar11) -
                                                                  DOUBLE_803e3038) * dVar16));
              local_a0 = CONCAT31(CONCAT21(CONCAT11(DAT_803de673,DAT_803de672),DAT_803de671),
                                  DAT_803de670);
              local_9c = local_a0;
              FUN_80075534(iVar5,iVar7,iVar6,iVar8,&local_9c);
            }
          }
          DAT_803de696 = (ushort)DAT_803de688;
          DAT_803de694 = DAT_803de698 + 0xb;
          DAT_803de698 = DAT_803de694;
          DAT_803de69a = DAT_803de696;
        }
        else {
          if ((9 < uVar13) || (uVar13 < 9)) goto LAB_80137674;
          uVar12 = (uint)DAT_803dc878;
          iVar5 = (uint)DAT_803de69a - (DAT_803de69a / uVar12) * uVar12;
          if (iVar5 != 0) {
            uVar12 = uVar12 - iVar5;
          }
        }
      }
      else if (uVar13 < 0x81) {
LAB_80137674:
        uVar12 = FUN_80136dc8(uVar4,uVar13);
      }
      else {
        uVar2 = *(undefined4 *)pbVar15;
        pbVar15 = pbVar14 + 5;
        if (DAT_803de68c != 0) {
          local_90 = uVar2;
          local_8c = uVar2;
          FUN_8025c428(1,(byte *)&local_90);
        }
      }
    }
    else if (uVar13 == 0x86) {
      bVar1 = *pbVar15;
      pbVar15 = pbVar14 + 3;
      DAT_803dc878 = CONCAT11(pbVar14[2],bVar1);
    }
    else if (uVar13 < 0x86) {
      if (uVar13 == 0x84) {
        DAT_803de690 = 1;
      }
      else if (uVar13 < 0x84) {
        DAT_803de690 = 0;
      }
      else {
        bVar1 = *pbVar15;
        pbVar15 = pbVar14 + 5;
        if (DAT_803de68c == 0) {
          DAT_803de670 = pbVar14[4];
          DAT_803de671 = pbVar14[3];
          DAT_803de672 = pbVar14[2];
          DAT_803de673 = bVar1;
          FUN_8005d294(uVar4,bVar1,pbVar14[2],pbVar14[3],pbVar14[4]);
        }
      }
    }
    else {
      if (0x87 < uVar13) goto LAB_80137674;
      DAT_803de660 = *pbVar15;
      DAT_803de661 = pbVar14[2];
      pbVar15 = pbVar14 + 3;
    }
    if (((DAT_803de690 != 0) && (0x1f < uVar13)) && (uVar13 < 0x80)) {
      uVar12 = 7;
    }
    uVar13 = DAT_803de69a + uVar12 & 0xffff;
    DAT_803de69a = (ushort)(DAT_803de69a + uVar12);
    local_60 = 0x43300000;
    uStack_64 = (uint)DAT_803de660;
    local_68 = 0x43300000;
    dVar16 = (double)(FLOAT_803de658 + (float)((double)CONCAT44(0x43300000,uStack_64) - dVar17));
    uStack_6c = DAT_803de676 - 0x10 ^ 0x80000000;
    local_70 = 0x43300000;
    pbVar14 = pbVar15;
    uStack_5c = uVar13;
    if ((float)((double)CONCAT44(0x43300000,uStack_6c) - dVar18) <
        (float)((double)(float)((double)CONCAT44(0x43300000,uVar13) - dVar17) * dVar16)) {
      if (DAT_803de68c == 0) {
        uVar9 = DAT_803de698 + 10;
        uVar11 = (uint)DAT_803de694;
        uStack_5c = (uint)DAT_803de696;
        uVar12 = countLeadingZeros(uVar13 - uStack_5c);
        uVar3 = countLeadingZeros(uVar9 - uVar11);
        if (uVar12 >> 5 == 0 && uVar3 >> 5 == 0) {
          if (1 < uStack_5c) {
            uStack_5c = uStack_5c - 2;
          }
          local_60 = 0x43300000;
          iVar5 = FUN_80286718((double)(float)((double)(float)((double)CONCAT44(0x43300000,uStack_5c
                                                                               ) - DOUBLE_803e3038)
                                              * dVar16));
          local_68 = 0x43300000;
          uStack_64 = uVar13 + 2;
          iVar6 = FUN_80286718((double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                                uVar13 + 2) -
                                                              DOUBLE_803e3038) * dVar16));
          local_70 = 0x43300000;
          uStack_74 = (uint)DAT_803de661;
          local_78 = 0x43300000;
          dVar16 = (double)(FLOAT_803de65c +
                           (float)((double)CONCAT44(0x43300000,uStack_74) - DOUBLE_803e3038));
          uStack_6c = uVar11;
          iVar7 = FUN_80286718((double)(float)((double)(float)((double)CONCAT44(0x43300000,uVar11) -
                                                              DOUBLE_803e3038) * dVar16));
          local_80 = 0x43300000;
          uStack_7c = uVar9;
          iVar8 = FUN_80286718((double)(float)((double)(float)((double)CONCAT44(0x43300000,uVar9) -
                                                              DOUBLE_803e3038) * dVar16));
          local_a8 = CONCAT31(CONCAT21(CONCAT11(DAT_803de673,DAT_803de672),DAT_803de671),
                              DAT_803de670);
          local_a4 = local_a8;
          FUN_80075534(iVar5,iVar7,iVar6,iVar8,&local_a4);
          uVar13 = uStack_5c;
        }
      }
      uStack_5c = uVar13;
      DAT_803de696 = (ushort)DAT_803de688;
      DAT_803de694 = DAT_803de698 + 0xb;
      DAT_803de698 = DAT_803de694;
      DAT_803de69a = DAT_803de696;
    }
  } while( true );
}

