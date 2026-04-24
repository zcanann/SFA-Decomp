// Function: FUN_8012c9fc
// Entry: 8012c9fc
// Size: 3456 bytes

/* WARNING: Removing unreachable block (ram,0x8012d754) */
/* WARNING: Removing unreachable block (ram,0x8012d744) */
/* WARNING: Removing unreachable block (ram,0x8012d73c) */
/* WARNING: Removing unreachable block (ram,0x8012d74c) */
/* WARNING: Removing unreachable block (ram,0x8012d75c) */

void FUN_8012c9fc(void)

{
  bool bVar1;
  ushort uVar2;
  byte bVar3;
  int iVar4;
  int iVar5;
  ushort uVar6;
  char cVar8;
  char cVar9;
  undefined2 uVar7;
  uint uVar10;
  uint uVar11;
  int iVar12;
  uint uVar13;
  byte *pbVar14;
  uint uVar15;
  uint uVar16;
  int iVar17;
  short sVar18;
  short sVar19;
  undefined4 uVar20;
  double dVar21;
  undefined8 in_f27;
  double dVar22;
  undefined8 in_f28;
  double dVar23;
  undefined8 in_f29;
  double dVar24;
  undefined8 in_f30;
  double dVar25;
  undefined8 in_f31;
  double dVar26;
  double local_b0;
  double local_98;
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar20 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  __psq_st0(auStack72,(int)((ulonglong)in_f27 >> 0x20),0);
  __psq_st1(auStack72,(int)in_f27,0);
  FUN_802860c0();
  if (DAT_803dd780 == '\0') {
    if (DAT_803dd776 == 0) {
      FUN_80019908(0xff,0xff,0xff,0xff);
      FUN_8007719c((double)FLOAT_803e21a0,(double)FLOAT_803e21a4,DAT_803a89d8,0xff,0x100);
      FUN_8007681c((double)FLOAT_803e1f9c,(double)FLOAT_803e21a4,DAT_803a89e4,0xff,0x100,0xa8,5,0);
      FUN_8007681c((double)FLOAT_803e21a0,(double)FLOAT_803e1edc,DAT_803a89dc,0xff,0x100,5,0x30,0);
      FUN_8007681c((double)FLOAT_803e1f9c,(double)FLOAT_803e1edc,DAT_803a89e0,0xff,0x100,0xa8,0x30,0
                  );
      FUN_8007681c((double)FLOAT_803e1f9c,(double)FLOAT_803e21a8,DAT_803a89e4,0xff,0x100,0xa8,5,2);
      FUN_8007681c((double)FLOAT_803e21ac,(double)FLOAT_803e1edc,DAT_803a89dc,0xff,0x100,5,0x30,1);
      FUN_8007681c((double)FLOAT_803e21ac,(double)FLOAT_803e21a8,DAT_803a89d8,0xff,0x100,5,5,3);
      FUN_8007681c((double)FLOAT_803e21ac,(double)FLOAT_803e21a4,DAT_803a89d8,0xff,0x100,5,5,1);
      FUN_8007681c((double)FLOAT_803e21a0,(double)FLOAT_803e21a8,DAT_803a89d8,0xff,0x100,5,5,2);
      FUN_8007719c((double)FLOAT_803e1ff0,(double)FLOAT_803e21b0,DAT_803a8aac,0xff,0x100);
      iVar12 = FUN_80019570(0x2ac);
      if (1 < *(ushort *)(iVar12 + 2)) {
        FUN_80015dc8(*(undefined4 *)(*(int *)(iVar12 + 8) + 4),0x93,0x69,0x17f);
      }
      FUN_8007719c((double)FLOAT_803e1e9c,(double)FLOAT_803e21b4,DAT_803a8abc,0xff,0x100);
      if (2 < *(ushort *)(iVar12 + 2)) {
        FUN_80015dc8(*(undefined4 *)(*(int *)(iVar12 + 8) + 8),0x93,0x51,0x194);
      }
      FUN_8007719c((double)FLOAT_803e21b8,(double)FLOAT_803e21a4,DAT_803a89d8,0xff,0x100);
      FUN_8007681c((double)FLOAT_803e21bc,(double)FLOAT_803e21a4,DAT_803a89e4,0xff,0x100,0xa8,5,0);
      FUN_8007681c((double)FLOAT_803e21b8,(double)FLOAT_803e1edc,DAT_803a89dc,0xff,0x100,5,0x30,0);
      FUN_8007681c((double)FLOAT_803e21bc,(double)FLOAT_803e1edc,DAT_803a89e0,0xff,0x100,0xa8,0x30,0
                  );
      FUN_8007681c((double)FLOAT_803e21bc,(double)FLOAT_803e21a8,DAT_803a89e4,0xff,0x100,0xa8,5,2);
      FUN_8007681c((double)FLOAT_803e21c0,(double)FLOAT_803e1edc,DAT_803a89dc,0xff,0x100,5,0x30,1);
      FUN_8007681c((double)FLOAT_803e21c0,(double)FLOAT_803e21a8,DAT_803a89d8,0xff,0x100,5,5,3);
      FUN_8007681c((double)FLOAT_803e21c0,(double)FLOAT_803e21a4,DAT_803a89d8,0xff,0x100,5,5,1);
      FUN_8007681c((double)FLOAT_803e21b8,(double)FLOAT_803e21a8,DAT_803a89d8,0xff,0x100,5,5,2);
      FUN_8007719c((double)FLOAT_803e21c4,(double)FLOAT_803e21c8,DAT_803a8ab0,0xff,0x100);
      if (4 < *(ushort *)(iVar12 + 2)) {
        FUN_80015dc8(*(undefined4 *)(*(int *)(iVar12 + 8) + 0x10),0x93,0x20c,0x17f);
      }
      FUN_8007719c((double)FLOAT_803e21cc,(double)FLOAT_803e1fb8,DAT_803a8ab4,0xff,0x100);
      if (5 < *(ushort *)(iVar12 + 2)) {
        FUN_80015dc8(*(undefined4 *)(*(int *)(iVar12 + 8) + 0x14),0x93,0x1f6,0x195);
      }
    }
    else {
      uVar2 = DAT_803dd776 * 0xf;
      if (0xff < (short)uVar2) {
        uVar2 = 0xff;
      }
      iVar12 = DAT_803dd776 + -0x14;
      if ((short)iVar12 < 0) {
        iVar12 = 0;
      }
      uVar6 = (ushort)(iVar12 << 4);
      if ((int)(uint)DAT_802c7586 < (int)(short)uVar6) {
        uVar6 = DAT_802c7586;
      }
      uVar11 = (uint)DAT_802c7594;
      uVar10 = (uint)DAT_802c7596;
      iVar12 = (int)(short)uVar6;
      iVar17 = (int)DAT_802c7582;
      uVar15 = uVar11 - 5;
      uVar16 = uVar10 - 5;
      FUN_8007719c((double)(float)((double)CONCAT44(0x43300000,uVar15 ^ 0x80000000) -
                                  DOUBLE_803e1e78),
                   (double)(float)((double)CONCAT44(0x43300000,uVar16 ^ 0x80000000) -
                                  DOUBLE_803e1e78),DAT_803a89d8,uVar2 & 0xff,0x100);
      FUN_8007681c((double)(float)((double)CONCAT44(0x43300000,uVar11 ^ 0x80000000) -
                                  DOUBLE_803e1e78),
                   (double)(float)((double)CONCAT44(0x43300000,uVar16 ^ 0x80000000) -
                                  DOUBLE_803e1e78),DAT_803a89e4,uVar2 & 0xff,0x100,iVar17,5,0);
      FUN_8007681c((double)(float)((double)CONCAT44(0x43300000,uVar15 ^ 0x80000000) -
                                  DOUBLE_803e1e78),
                   (double)(float)((double)CONCAT44(0x43300000,uVar10 ^ 0x80000000) -
                                  DOUBLE_803e1e78),DAT_803a89dc,uVar2 & 0xff,0x100,5,iVar12,0);
      FUN_8007681c((double)(float)((double)CONCAT44(0x43300000,uVar11 ^ 0x80000000) -
                                  DOUBLE_803e1e78),
                   (double)(float)((double)CONCAT44(0x43300000,uVar10 ^ 0x80000000) -
                                  DOUBLE_803e1e78),DAT_803a89e0,uVar2 & 0xff,0x100,iVar17,iVar12,0);
      uVar13 = uVar10 + iVar12;
      FUN_8007681c((double)(float)((double)CONCAT44(0x43300000,uVar11 ^ 0x80000000) -
                                  DOUBLE_803e1e78),
                   (double)(float)((double)CONCAT44(0x43300000,uVar13 ^ 0x80000000) -
                                  DOUBLE_803e1e78),DAT_803a89e4,uVar2 & 0xff,0x100,iVar17,5,2);
      uVar11 = uVar11 + iVar17;
      FUN_8007681c((double)(float)((double)CONCAT44(0x43300000,uVar11 ^ 0x80000000) -
                                  DOUBLE_803e1e78),
                   (double)(float)((double)CONCAT44(0x43300000,uVar10 ^ 0x80000000) -
                                  DOUBLE_803e1e78),DAT_803a89dc,uVar2 & 0xff,0x100,5,iVar12,1);
      local_b0 = (double)CONCAT44(0x43300000,uVar13 ^ 0x80000000);
      FUN_8007681c((double)(float)((double)CONCAT44(0x43300000,uVar11 ^ 0x80000000) -
                                  DOUBLE_803e1e78),(double)(float)(local_b0 - DOUBLE_803e1e78),
                   DAT_803a89d8,uVar2 & 0xff,0x100,5,5,3);
      FUN_8007681c((double)(float)((double)CONCAT44(0x43300000,uVar11 ^ 0x80000000) -
                                  DOUBLE_803e1e78),
                   (double)(float)((double)CONCAT44(0x43300000,uVar16 ^ 0x80000000) -
                                  DOUBLE_803e1e78),DAT_803a89d8,uVar2 & 0xff,0x100,5,5,1);
      local_98 = (double)CONCAT44(0x43300000,uVar15 ^ 0x80000000);
      FUN_8007681c((double)(float)(local_98 - DOUBLE_803e1e78),
                   (double)(float)((double)CONCAT44(0x43300000,uVar13 ^ 0x80000000) -
                                  DOUBLE_803e1e78),DAT_803a89d8,uVar2 & 0xff,0x100,5,5,2);
      iVar12 = 0;
      pbVar14 = &DAT_803dba94;
      DAT_802c758a = uVar6;
      do {
        iVar17 = FUN_8001ffb4(*(undefined2 *)(&DAT_8031b08a + (uint)*pbVar14 * 0x1c));
        if (iVar17 != 0) {
          cVar9 = (&DAT_803dba94)[iVar12];
          goto LAB_8012cdec;
        }
        pbVar14 = pbVar14 + 1;
        iVar12 = iVar12 + 1;
      } while (iVar12 < 5);
      cVar9 = -1;
LAB_8012cdec:
      iVar12 = FUN_8001ffb4(0x63c);
      iVar17 = FUN_8001ffb4(0x4e9);
      iVar4 = FUN_8001ffb4(0x5f3);
      iVar5 = FUN_8001ffb4(0x5f4);
      iVar17 = iVar17 + iVar12 + iVar4 + iVar5;
      iVar12 = FUN_8001ffb4(0x123);
      if (iVar12 != 0) {
        iVar17 = iVar17 + 1;
      }
      iVar12 = FUN_8001ffb4(0x2e8);
      if (iVar12 != 0) {
        iVar17 = iVar17 + 1;
      }
      iVar12 = FUN_8001ffb4(0x83b);
      if (iVar12 != 0) {
        iVar17 = iVar17 + 1;
      }
      iVar12 = FUN_8001ffb4(0x83c);
      if (iVar12 != 0) {
        iVar17 = iVar17 + 1;
      }
      bVar3 = DAT_803dba94;
      if ((((iVar17 < (int)(uint)(byte)(&DAT_8031b08c)[(uint)DAT_803dba94 * 0x1c]) &&
           (bVar3 = bRam803dba95,
           iVar17 < (int)(uint)(byte)(&DAT_8031b08c)[(uint)bRam803dba95 * 0x1c])) &&
          (bVar3 = bRam803dba96,
          iVar17 < (int)(uint)(byte)(&DAT_8031b08c)[(uint)bRam803dba96 * 0x1c])) &&
         ((bVar3 = bRam803dba97,
          iVar17 < (int)(uint)(byte)(&DAT_8031b08c)[(uint)bRam803dba97 * 0x1c] &&
          (bVar3 = bRam803dba98,
          iVar17 < (int)(uint)(byte)(&DAT_8031b08c)[(uint)bRam803dba98 * 0x1c])))) {
        bVar3 = 0xff;
      }
      uVar11 = (uint)(char)bVar3;
      uVar6 = FUN_800ea2bc();
      bVar1 = 0xad < uVar6;
      uVar10 = (uint)DAT_803dd77a;
      if ((uVar10 == 2) && (bVar1)) {
        uVar7 = 0x574;
      }
      else if (((int)cVar9 == uVar10) && (uVar11 != uVar10)) {
        uVar7 = *(undefined2 *)(&DAT_8031b074 + uVar10 * 0x1c);
      }
      else if (uVar10 == 2) {
        cVar8 = (**(code **)(*DAT_803dcaac + 0x40))(0xd);
        if ((cVar8 != '\x02') || (bVar1)) {
          if ((int)cVar9 == uVar11) {
            iVar12 = FUN_8001ffb4(*(undefined2 *)(&DAT_8031b08e + uVar11 * 0x1c));
            if (iVar12 == 0) {
              uVar7 = *(undefined2 *)(&DAT_8031b078 + uVar11 * 0x1c);
            }
            else {
              uVar7 = 0x578;
            }
          }
          else {
            uVar7 = *(undefined2 *)(&DAT_8031b076 + (uint)DAT_803dd77a * 0x1c);
          }
        }
        else {
          uVar7 = 0x577;
        }
      }
      else if (((uVar10 != 0) || (cVar9 = (**(code **)(*DAT_803dcaac + 0x40))(0xd), cVar9 != '\x02')
               ) || (bVar1)) {
        uVar7 = *(undefined2 *)(&DAT_8031b076 + (uint)DAT_803dd77a * 0x1c);
      }
      else {
        uVar7 = 0x568;
      }
      FUN_80016870(uVar7);
      DAT_803dd77c = DAT_803dd77c + 1;
      FUN_8007719c((double)FLOAT_803e2198,(double)FLOAT_803e219c,DAT_803a89d8,uVar2 & 0xff,0x100);
      FUN_8007681c((double)FLOAT_803e1f48,(double)FLOAT_803e219c,DAT_803a89e4,uVar2 & 0xff,0x100,
                   0x82,5,0);
      FUN_8007681c((double)FLOAT_803e2198,(double)FLOAT_803e1e9c,DAT_803a89dc,uVar2 & 0xff,0x100,5,
                   0x96,0);
      FUN_8007681c((double)FLOAT_803e1f48,(double)FLOAT_803e1ecc,DAT_803a89e4,uVar2 & 0xff,0x100,
                   0x82,5,2);
      FUN_8007681c((double)FLOAT_803e2058,(double)FLOAT_803e1e9c,DAT_803a89dc,uVar2 & 0xff,0x100,5,
                   0x96,1);
      FUN_8007681c((double)FLOAT_803e2058,(double)FLOAT_803e1ecc,DAT_803a89d8,uVar2 & 0xff,0x100,5,5
                   ,3);
      FUN_8007681c((double)FLOAT_803e2058,(double)FLOAT_803e219c,DAT_803a89d8,uVar2 & 0xff,0x100,5,5
                   ,1);
      FUN_8007681c((double)FLOAT_803e2198,(double)FLOAT_803e1ecc,DAT_803a89d8,uVar2 & 0xff,0x100,5,5
                   ,2);
      iVar12 = 0;
      sVar18 = 0;
      sVar19 = 0;
      dVar22 = (double)FLOAT_803e204c;
      dVar25 = (double)FLOAT_803e2050;
      dVar26 = (double)FLOAT_803e2010;
      dVar24 = DOUBLE_803e1e78;
      do {
        dVar21 = (double)FUN_80293234(sVar18 + DAT_803dd77c * 0x1838);
        dVar23 = (double)(float)(dVar22 * dVar21);
        dVar21 = (double)FUN_80293234(sVar19 + DAT_803dd77c * 4000);
        dVar21 = (double)(float)(dVar22 * dVar21 + dVar23);
        uVar10 = (uint)((float)((double)CONCAT44(0x43300000,(int)(short)uVar2 ^ 0x80000000U) -
                               dVar24) * (float)(dVar25 + dVar21));
        if ((int)uVar10 < 0) {
          uVar10 = 0;
        }
        iVar17 = FUN_800221a0(0,0x1e);
        iVar4 = FUN_800221a0(0,0x1e);
        if (0xff < (int)uVar10) {
          uVar10 = 0xff;
        }
        FUN_80075fc8((double)FLOAT_803e1f48,
                     (double)(float)((double)CONCAT44(0x43300000,iVar12 + 0x32U ^ 0x80000000) -
                                    dVar24),DAT_803a8b00,uVar10 & 0xff,0x100,0x82,2,iVar4 << 1,
                     iVar17 << 1);
        uVar10 = (uint)((float)((double)CONCAT44(0x43300000,(int)(short)uVar2 ^ 0x80000000U) -
                               dVar24) * (float)(dVar26 + dVar21));
        if ((int)uVar10 < 0) {
          uVar10 = 0;
        }
        iVar17 = FUN_800221a0(0,0x1e);
        iVar4 = FUN_800221a0(0,0x1e);
        if (0xff < (int)uVar10) {
          uVar10 = 0xff;
        }
        FUN_80075fc8((double)FLOAT_803e1f48,
                     (double)(float)((double)CONCAT44(0x43300000,iVar12 + 0x34U ^ 0x80000000) -
                                    dVar24),DAT_803a8b00,uVar10 & 0xff,0x100,0x82,2,iVar4 << 1,
                     iVar17 << 1);
        sVar18 = sVar18 + 0x3520;
        sVar19 = sVar19 + 8000;
        iVar12 = iVar12 + 4;
      } while (iVar12 < 0x96);
      FUN_80016810(0x3dd,100,0x15e);
    }
  }
  __psq_l0(auStack8,uVar20);
  __psq_l1(auStack8,uVar20);
  __psq_l0(auStack24,uVar20);
  __psq_l1(auStack24,uVar20);
  __psq_l0(auStack40,uVar20);
  __psq_l1(auStack40,uVar20);
  __psq_l0(auStack56,uVar20);
  __psq_l1(auStack56,uVar20);
  __psq_l0(auStack72,uVar20);
  __psq_l1(auStack72,uVar20);
  FUN_8028610c();
  return;
}

