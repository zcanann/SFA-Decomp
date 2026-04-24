// Function: FUN_80125424
// Entry: 80125424
// Size: 1920 bytes

/* WARNING: Removing unreachable block (ram,0x80125b7c) */
/* WARNING: Removing unreachable block (ram,0x80125b6c) */
/* WARNING: Removing unreachable block (ram,0x80125b64) */
/* WARNING: Removing unreachable block (ram,0x80125b74) */
/* WARNING: Removing unreachable block (ram,0x80125b84) */

void FUN_80125424(void)

{
  ushort uVar1;
  ushort uVar3;
  uint uVar2;
  int iVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  uint uVar8;
  short sVar9;
  short sVar10;
  uint uVar11;
  undefined4 uVar12;
  double dVar13;
  double dVar14;
  undefined8 in_f27;
  double dVar15;
  undefined8 in_f28;
  double dVar16;
  undefined8 in_f29;
  undefined8 in_f30;
  double dVar17;
  undefined8 in_f31;
  double dVar18;
  double local_b8;
  double local_a8;
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar12 = 0;
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
  if (DAT_803dd85a != '\0') {
    if (DAT_803dd7a8 == '\0') {
      DAT_803dd858 = DAT_803dd858 + (ushort)DAT_803db410 * 5;
      if (0x152 < DAT_803dd858) {
        DAT_803dd858 = 0x152;
        DAT_803dd85a = '\0';
        if (*(int *)(&DAT_8031af34 + (uint)DAT_803dd85b * 0xc) != -1) {
          FUN_8000d01c();
          FUN_8000cf54(0);
        }
      }
      DAT_803dd856 = DAT_803dd856 + (ushort)DAT_803db410 * -10;
      DAT_803dd854 = DAT_803dd854 + (ushort)DAT_803db410 * -0x17;
    }
    else {
      DAT_803dd858 = DAT_803dd858 + (ushort)DAT_803db410 * -5;
      if (DAT_803dd858 < 0x122) {
        DAT_803dd858 = 0x122;
      }
      DAT_803dd856 = DAT_803dd856 + (ushort)DAT_803db410 * 10;
      DAT_803dd854 = DAT_803dd854 + (ushort)DAT_803db410 * 0x17;
    }
    uVar1 = DAT_803dd858;
    if ((short)DAT_803dd854 < 0) {
      uVar3 = 0;
    }
    else {
      uVar3 = DAT_803dd854;
      if (0xff < (short)DAT_803dd854) {
        uVar3 = 0xff;
      }
    }
    uVar2 = (uint)DAT_803dd856;
    if (0x6e < uVar2) {
      uVar2 = 0x6e;
    }
    uVar11 = (uint)DAT_803dd858;
    uVar7 = (uint)(byte)(&DAT_8031af3a)[(uint)DAT_803dd85b * 0xc];
    if (uVar7 == 2) {
      uVar8 = 0x186;
    }
    else if ((uVar7 < 2) || (3 < uVar7)) {
      uVar8 = 0x19a;
    }
    else {
      uVar8 = 0x195;
    }
    DAT_803dd854 = uVar3;
    DAT_803dd856 = (short)uVar2;
    FUN_8025d324(0x1ea,uVar11,0x78,uVar2);
    FUN_80076510((double)FLOAT_803e2040,
                 (double)(float)((double)CONCAT44(0x43300000,uVar11 ^ 0x80000000) - DOUBLE_803e1e78)
                 ,0x78,uVar2);
    dVar13 = (double)FUN_8000fc34();
    FLOAT_803dbaa4 = (float)dVar13;
    FUN_8000fc3c((double)FLOAT_803e2044);
    FUN_8000f458(1);
    DAT_803dd7e0 = FUN_8000fac4();
    FUN_8000facc();
    dVar13 = (double)FLOAT_803e1e3c;
    FUN_8000f510(dVar13,dVar13,dVar13);
    FUN_8000f4e0(0x8000,0,0);
    FUN_8000f564();
    FUN_8000fb00();
    local_b8 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803dccf0 + 4));
    FUN_8025d300((double)FLOAT_803e2048,
                 (double)((float)((double)CONCAT44(0x43300000,uVar8 ^ 0x80000000) - DOUBLE_803e1e78)
                         - FLOAT_803e2024),(double)(float)(local_b8 - DOUBLE_803e1e88),
                 (double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803dccf0 + 8)) -
                                DOUBLE_803e1e88),(double)FLOAT_803e1e3c,(double)FLOAT_803e1e68);
    if ((&DAT_803a93f8)[uVar7] != 0) {
      FUN_8002fa48((double)*(float *)(&DAT_8031bfa8 + uVar7 * 4),(double)FLOAT_803db414,
                   (&DAT_803a93f8)[uVar7],0);
      if (0x90000000 < *(uint *)((&DAT_803a93f8)[uVar7] + 0x4c)) {
        *(undefined4 *)((&DAT_803a93f8)[uVar7] + 0x4c) = 0;
      }
      *(undefined *)((&DAT_803a93f8)[uVar7] + 0x37) = 0xff;
      FUN_8003b958(0,0,0,0,(&DAT_803a93f8)[uVar7],1);
      iVar4 = FUN_8002b588((&DAT_803a93f8)[uVar7]);
      *(ushort *)(iVar4 + 0x18) = *(ushort *)(iVar4 + 0x18) & 0xfff7;
    }
    FUN_8000f458(0);
    if (DAT_803dd7e0 != 0) {
      FUN_8000fad8();
    }
    FUN_8000f564();
    FUN_8000fc3c((double)FLOAT_803dbaa4);
    FUN_8000fb00();
    FUN_8000f780();
    FUN_8025d324(0,0,0x280,0x1e0);
    DAT_803dd77c = DAT_803dd77c + 1;
    sVar10 = 0;
    sVar9 = 0;
    dVar15 = (double)FLOAT_803e204c;
    dVar17 = (double)FLOAT_803e2050;
    dVar18 = (double)FLOAT_803e2010;
    dVar13 = DOUBLE_803e1e78;
    for (iVar4 = 0; iVar4 < (int)uVar2; iVar4 = iVar4 + 4) {
      dVar14 = (double)FUN_80293234(sVar10 + DAT_803dd77c * 0x1838);
      dVar16 = (double)(float)(dVar15 * dVar14);
      dVar14 = (double)FUN_80293234(sVar9 + DAT_803dd77c * 4000);
      dVar14 = (double)(float)(dVar15 * dVar14 + dVar16);
      uVar7 = (uint)((float)((double)CONCAT44(0x43300000,(int)(short)uVar3 ^ 0x80000000U) - dVar13)
                    * (float)(dVar17 + dVar14));
      if ((int)uVar7 < 0) {
        uVar7 = 0;
      }
      iVar5 = FUN_800221a0(0,0x1e);
      iVar6 = FUN_800221a0(0,0x1e);
      if (0xff < (int)uVar7) {
        uVar7 = 0xff;
      }
      FUN_80075fc8((double)FLOAT_803e2040,
                   (double)(float)((double)CONCAT44(0x43300000,uVar11 + iVar4 ^ 0x80000000) - dVar13
                                  ),DAT_803a8b00,uVar7 & 0xff,0x100,0x78,2,iVar6 << 1,iVar5 << 1);
      uVar7 = (uint)((float)((double)CONCAT44(0x43300000,(int)(short)uVar3 ^ 0x80000000U) - dVar13)
                    * (float)(dVar18 + dVar14));
      if ((int)uVar7 < 0) {
        uVar7 = 0;
      }
      iVar5 = FUN_800221a0(0,0x1e);
      iVar6 = FUN_800221a0(0,0x1e);
      if (0xff < (int)uVar7) {
        uVar7 = 0xff;
      }
      FUN_80075fc8((double)FLOAT_803e2040,
                   (double)(float)((double)CONCAT44(0x43300000,uVar11 + iVar4 + 2 ^ 0x80000000) -
                                  dVar13),DAT_803a8b00,uVar7 & 0xff,0x100,0x78,2,iVar6 << 1,
                   iVar5 << 1);
      sVar10 = sVar10 + 0x3520;
      sVar9 = sVar9 + 8000;
    }
    uVar11 = (uint)(short)uVar1;
    uVar7 = uVar11 - 5;
    FUN_8007719c((double)FLOAT_803e2054,
                 (double)(float)((double)CONCAT44(0x43300000,uVar7 ^ 0x80000000) - DOUBLE_803e1e78),
                 DAT_803a89d8,uVar3 & 0xff,0x100);
    local_a8 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
    FUN_8007681c((double)FLOAT_803e2040,(double)(float)(local_a8 - DOUBLE_803e1e78),DAT_803a89e4,
                 uVar3 & 0xff,0x100,0x78,5,0);
    iVar4 = (int)(short)uVar2;
    FUN_8007681c((double)FLOAT_803e2054,
                 (double)(float)((double)CONCAT44(0x43300000,uVar11 ^ 0x80000000) - DOUBLE_803e1e78)
                 ,DAT_803a89dc,uVar3 & 0xff,0x100,5,iVar4,0);
    uVar2 = uVar11 + iVar4;
    local_b8 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    FUN_8007681c((double)FLOAT_803e2040,(double)(float)(local_b8 - DOUBLE_803e1e78),DAT_803a89e4,
                 uVar3 & 0xff,0x100,0x78,5,2);
    FUN_8007681c((double)FLOAT_803e2058,
                 (double)(float)((double)CONCAT44(0x43300000,uVar11 ^ 0x80000000) - DOUBLE_803e1e78)
                 ,DAT_803a89dc,uVar3 & 0xff,0x100,5,iVar4,1);
    FUN_8007681c((double)FLOAT_803e2058,
                 (double)(float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e1e78),
                 DAT_803a89d8,uVar3 & 0xff,0x100,5,5,3);
    FUN_8007681c((double)FLOAT_803e2058,
                 (double)(float)((double)CONCAT44(0x43300000,uVar7 ^ 0x80000000) - DOUBLE_803e1e78),
                 DAT_803a89d8,uVar3 & 0xff,0x100,5,5,1);
    FUN_8007681c((double)FLOAT_803e2054,
                 (double)(float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e1e78),
                 DAT_803a89d8,uVar3 & 0xff,0x100,5,5,2);
  }
  __psq_l0(auStack8,uVar12);
  __psq_l1(auStack8,uVar12);
  __psq_l0(auStack24,uVar12);
  __psq_l1(auStack24,uVar12);
  __psq_l0(auStack40,uVar12);
  __psq_l1(auStack40,uVar12);
  __psq_l0(auStack56,uVar12);
  __psq_l1(auStack56,uVar12);
  __psq_l0(auStack72,uVar12);
  __psq_l1(auStack72,uVar12);
  FUN_8028610c();
  return;
}

