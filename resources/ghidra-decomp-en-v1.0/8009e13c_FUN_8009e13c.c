// Function: FUN_8009e13c
// Entry: 8009e13c
// Size: 2984 bytes

/* WARNING: Removing unreachable block (ram,0x8009ecbc) */
/* WARNING: Removing unreachable block (ram,0x8009ecac) */
/* WARNING: Removing unreachable block (ram,0x8009ec9c) */
/* WARNING: Removing unreachable block (ram,0x8009eae4) */
/* WARNING: Removing unreachable block (ram,0x8009eca4) */
/* WARNING: Removing unreachable block (ram,0x8009ecb4) */
/* WARNING: Removing unreachable block (ram,0x8009ecc4) */
/* WARNING: Removing unreachable block (ram,0x8009eaec) */
/* WARNING: Removing unreachable block (ram,0x8009eaf4) */

void FUN_8009e13c(void)

{
  float fVar1;
  float fVar2;
  float fVar3;
  byte bVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  uint uVar8;
  int iVar9;
  int iVar10;
  short sVar12;
  short *psVar11;
  short sVar13;
  int iVar14;
  char cVar15;
  char cVar16;
  char cVar17;
  char cVar18;
  int iVar19;
  int iVar20;
  uint uVar21;
  int iVar22;
  int iVar23;
  undefined4 uVar24;
  undefined4 uVar25;
  undefined4 uVar26;
  double dVar27;
  undefined8 in_f26;
  double dVar28;
  undefined8 in_f27;
  double dVar29;
  undefined8 in_f28;
  undefined8 in_f29;
  double dVar30;
  undefined8 in_f30;
  double dVar31;
  undefined8 in_f31;
  double dVar32;
  undefined8 uVar33;
  float local_f8;
  float local_f4;
  float local_f0;
  float local_ec;
  float local_e8;
  float local_e4;
  float local_e0;
  float local_dc;
  float local_d8;
  undefined4 local_d0;
  uint uStack204;
  double local_c8;
  double local_c0;
  int local_b8;
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar25 = 0x70007;
  uVar24 = 0;
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
  __psq_st0(auStack88,(int)((ulonglong)in_f26 >> 0x20),0);
  __psq_st1(auStack88,(int)in_f26,0);
  uVar33 = FUN_802860a8();
  iVar9 = FUN_80022a48();
  local_b8 = FUN_8002073c();
  FUN_8000faf4();
  FUN_800229f8(iVar9,(int)((ulonglong)uVar33 >> 0x20),0x7e);
  FUN_802573f8();
  FUN_80256978(9,1);
  FUN_80256978(0xb,1);
  FUN_80256978(0xd,1);
  FUN_8025d124(0);
  FUN_80259ea4(0,0,0,1,0,0,2);
  FUN_80259ea4(2,0,0,1,0,0,2);
  FUN_80259e58(1);
  FUN_80258b24(0);
  iVar10 = FUN_8000f54c();
  FUN_8025d0a8(iVar10,0);
  FUN_80246e80(iVar10,&DAT_803967c0);
  FUN_8007d670();
  FUN_800703c4();
  sVar12 = FUN_80008b4c(0xffffffff);
  if (sVar12 != 1) {
    psVar11 = (short *)FUN_8000faac();
    FUN_8005d0e8(0,0xff,0xff,0xff,0xff);
    cVar18 = -1;
    cVar17 = -1;
    cVar16 = -1;
    cVar15 = -1;
    iVar14 = 0;
    FUN_800229c4(0);
    iVar22 = 0;
    iVar9 = iVar9 + -0xa0;
    do {
      iVar23 = iVar9 + 0xa0;
      uVar8 = (uint)(*(byte *)(iVar9 + 0x12a) >> 1);
      iVar20 = (&DAT_8039b4d8)[uVar8 * 4];
      iVar19 = (&DAT_8039b4e0)[uVar8 * 4];
      if (((((1 << iVar22 & (&DAT_8039bc18)[(int)uVar33]) != 0) &&
           (bVar4 = *(byte *)(iVar9 + 299), (bVar4 >> 2 & 3) == 0)) && ((bVar4 >> 1 & 1) != 0)) &&
         ((*(short *)(iVar9 + 0xc6) != -1 && ((bVar4 & 1) == 0)))) {
        uStack204 = (int)*(short *)(iVar9 + 0xb6) ^ 0x80000000;
        fVar1 = FLOAT_803df358 * (float)((double)CONCAT44(0x43300000,uStack204) - DOUBLE_803df360);
        uVar8 = *(uint *)(iVar9 + 0x11c);
        if ((uVar8 & 0x800000) == 0) {
          if ((uVar8 & 0x200) == 0) {
            if ((*(uint *)(iVar9 + 0x120) & 0x400000) != 0) {
              uVar21 = (int)*(short *)(iVar9 + 0xa6) ^ 0x80000000;
              local_c0 = (double)CONCAT44(0x43300000,uVar21);
              if ((float)(local_c0 - DOUBLE_803df360) <= fVar1) {
                local_c0 = (double)CONCAT44(0x43300000,uVar21);
                fVar1 = (float)(local_c0 - DOUBLE_803df360) / fVar1;
                fVar2 = FLOAT_803df35c;
                if ((FLOAT_803df35c <= fVar1) && (fVar2 = fVar1, FLOAT_803df354 < fVar1)) {
                  fVar2 = FLOAT_803df354;
                }
                local_c0 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar9 + 0xaf));
                uVar21 = (uint)((float)(local_c0 - DOUBLE_803df378) * fVar2);
                local_c8 = (double)(longlong)(int)uVar21;
                goto LAB_8009e654;
              }
            }
            if ((uVar8 & 0x100) != 0) {
              uVar21 = (int)*(short *)(iVar9 + 0xa6) ^ 0x80000000;
              local_c0 = (double)CONCAT44(0x43300000,uVar21);
              if ((float)(local_c0 - DOUBLE_803df360) <= fVar1) {
                local_c0 = (double)CONCAT44(0x43300000,uVar21);
                fVar1 = (float)(local_c0 - DOUBLE_803df360) / fVar1;
                fVar2 = FLOAT_803df35c;
                if ((FLOAT_803df35c <= fVar1) && (fVar2 = fVar1, FLOAT_803df354 < fVar1)) {
                  fVar2 = FLOAT_803df354;
                }
                local_c0 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar9 + 0xaf));
                uVar21 = (uint)((float)(local_c0 - DOUBLE_803df378) * fVar2);
                local_c8 = (double)(longlong)(int)uVar21;
                goto LAB_8009e654;
              }
            }
            if ((uVar8 & 0x100) == 0) {
              uVar21 = (uint)*(byte *)(iVar9 + 0xaf);
            }
            else {
              local_c0 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar9 + 0xa6) ^ 0x80000000);
              fVar1 = (fVar1 - ((float)(local_c0 - DOUBLE_803df360) - fVar1)) / fVar1;
              fVar2 = FLOAT_803df35c;
              if ((FLOAT_803df35c <= fVar1) && (fVar2 = fVar1, FLOAT_803df354 < fVar1)) {
                fVar2 = FLOAT_803df354;
              }
              local_c0 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar9 + 0xaf));
              uVar21 = (uint)((float)(local_c0 - DOUBLE_803df378) * fVar2);
              local_c8 = (double)(longlong)(int)uVar21;
            }
          }
          else {
            local_c0 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar9 + 0xa6) ^ 0x80000000);
            local_c8 = (double)CONCAT44(0x43300000,uStack204);
            fVar1 = (float)(local_c0 - DOUBLE_803df360) / (float)(local_c8 - DOUBLE_803df360);
            fVar2 = FLOAT_803df35c;
            if ((FLOAT_803df35c <= fVar1) && (fVar2 = fVar1, FLOAT_803df354 < fVar1)) {
              fVar2 = FLOAT_803df354;
            }
            local_c0 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar9 + 0xaf));
            uVar21 = (uint)((float)(local_c0 - DOUBLE_803df378) * fVar2);
            local_c8 = (double)(longlong)(int)uVar21;
          }
        }
        else {
          local_c8 = (double)CONCAT44(0x43300000,uStack204);
          fVar1 = (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar9 + 0xa6) ^ 0x80000000) -
                         DOUBLE_803df360) / (float)(local_c8 - DOUBLE_803df360);
          fVar2 = FLOAT_803df35c;
          if ((FLOAT_803df35c <= fVar1) && (fVar2 = fVar1, FLOAT_803df354 < fVar1)) {
            fVar2 = FLOAT_803df354;
          }
          uStack204 = (uint)*(byte *)(iVar9 + 0xaf);
          local_c8 = (double)CONCAT44(0x43300000,uStack204 - 0xff ^ 0x80000000);
          uVar21 = (uint)((float)(local_c8 - DOUBLE_803df360) * fVar2 +
                         (float)((double)CONCAT44(0x43300000,uStack204) - DOUBLE_803df378));
        }
LAB_8009e654:
        local_d0 = 0x43300000;
        sVar12 = 0;
        sVar13 = 0;
        dVar32 = (double)*(float *)(iVar9 + 0x130);
        dVar31 = (double)*(float *)(iVar9 + 0x134);
        dVar30 = (double)*(float *)(iVar9 + 0x138);
        local_c0 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar9 + 0x124));
        dVar27 = (double)(FLOAT_803df410 * (float)(local_c0 - DOUBLE_803df378));
        if (((uVar8 & 0x400000) != 0) && (local_b8 == 0)) {
          dVar27 = (double)(float)((double)FLOAT_803df358 * dVar27);
          uVar8 = FUN_800221a0(1,10);
          local_c0 = (double)CONCAT44(0x43300000,uVar8 ^ 0x80000000);
          dVar27 = (double)(float)(dVar27 + (double)(float)(dVar27 / (double)(float)(local_c0 -
                                                                                    DOUBLE_803df360)
                                                           ));
        }
        uVar8 = *(uint *)(iVar9 + 0x11c);
        if ((uVar8 & 0x4000000) == 0) {
          sVar12 = 0;
          if ((uVar8 & 0x2000000) == 0) {
            if ((uVar8 & 0x80000) == 0) {
              sVar13 = -*psVar11;
            }
            else if (((*(uint *)(iVar9 + 0x120) & 0x400) == 0) || (iVar20 == 0)) {
              sVar13 = -*psVar11;
              sVar12 = psVar11[1];
            }
            else {
              local_e0 = *(float *)(psVar11 + 6) - *(float *)(iVar20 + 0x18);
              local_dc = *(float *)(psVar11 + 8) - *(float *)(iVar20 + 0x1c);
              local_d8 = *(float *)(psVar11 + 10) - *(float *)(iVar20 + 0x20);
              FUN_80247794(&local_e0,&local_e0);
              dVar29 = ABS((double)local_e0);
              dVar28 = ABS((double)local_d8);
              if (dVar29 <= dVar28) {
                FUN_800217c0(dVar28,(double)local_dc);
                sVar12 = FUN_800217c0(dVar28,(double)local_dc);
              }
              else {
                FUN_800217c0(dVar29,(double)local_dc);
                sVar12 = FUN_800217c0(dVar29,(double)local_dc);
              }
              sVar12 = sVar12 + -0x3800;
              sVar13 = FUN_800217c0((double)local_e0,(double)local_d8);
            }
          }
          else {
            sVar13 = 0;
          }
        }
        FUN_80292f14(sVar13,&local_f0,&local_ec);
        FUN_80292f14(sVar12,&local_e8,&local_e4);
        if ((*(uint *)(iVar9 + 0x120) & 0x4000000) == 0) {
          if ((*(uint *)(iVar9 + 0x120) & 0x8000000) != 0) {
            FUN_80292f14((uint)DAT_803dd26a + (iVar23 * 0x100 & 0xff00U) & 0xffff,&local_f4,
                         &local_f8);
          }
        }
        else {
          FUN_80292f14((uint)DAT_803dd268 + (iVar23 * 0x100 & 0xff00U) & 0xffff,&local_f4,&local_f8)
          ;
        }
        if ((iVar20 != 0) && ((*(uint *)(iVar9 + 0x120) & 0x80) != 0)) {
          uVar21 = (int)(uVar21 * *(byte *)(iVar20 + 0x36)) >> 8;
        }
        if (iVar14 != iVar19) {
          FUN_8004c2e4(iVar19,0);
          iVar14 = iVar19;
        }
        uVar8 = *(uint *)(iVar9 + 0x120);
        if ((uVar8 & 0x40) == 0) {
          if ((uVar8 & 0x8000) == 0) {
            if (cVar18 != '\x01') {
              FUN_800799c0();
              FUN_800796f0();
              FUN_80079804();
              cVar18 = '\x01';
            }
          }
          else if (cVar18 != '\x04') {
            FUN_8007c3d0(uVar8 & 0x20);
            cVar18 = '\x04';
          }
        }
        else if (cVar18 != '\0') {
          FUN_800799c0();
          FUN_80079180();
          FUN_80079804();
          cVar18 = '\0';
        }
        if ((*(uint *)(iVar9 + 0x120) & 1) == 0) {
          if (cVar15 != '\x01') {
            FUN_800702b8(1);
            FUN_8025bff0(7,0,0,7,0);
            cVar15 = '\x01';
          }
          if ((*(uint *)(iVar9 + 0x11c) & 0x10) == 0) {
            if (cVar16 != '\x02') {
              FUN_8000f780();
              FUN_80070310(1,3,0);
              cVar16 = '\x02';
            }
          }
          else if (cVar16 != '\x01') {
            FUN_8000f83c();
            FUN_80070310(1,3,0);
            cVar16 = '\x01';
          }
          if ((*(uint *)(iVar9 + 0x120) & 0x800) == 0) {
            if (cVar17 != '\x02') {
              FUN_8025c584(1,4,5,5);
              cVar17 = '\x02';
            }
          }
          else if (cVar17 != '\x01') {
            FUN_8025c584(1,4,1,5);
            cVar17 = '\x01';
          }
        }
        else if (cVar17 != '\0') {
          FUN_8000f780();
          FUN_80070310(1,3,1);
          FUN_8025c584(0,1,0,5);
          FUN_800702b8(0);
          FUN_8025bff0(4,0xfe,0,4,0xfe);
          cVar17 = '\0';
          cVar16 = '\0';
          cVar15 = '\0';
        }
        dVar32 = (double)(float)(dVar32 - (double)FLOAT_803dcdd8);
        dVar30 = (double)(float)(dVar30 - (double)FLOAT_803dcddc);
        FUN_8025889c(0x80,4,4);
        iVar20 = 4;
        iVar19 = iVar23;
        do {
          uVar26 = __psq_l0(iVar19,uVar25);
          fVar1 = (float)(dVar27 * (double)CONCAT44(uVar26,0x3f800000));
          uVar26 = __psq_l0(iVar19 + 2,uVar25);
          fVar2 = (float)(dVar27 * (double)CONCAT44(uVar26,0x3f800000));
          uVar26 = __psq_l0(iVar19 + 4,uVar25);
          fVar3 = (float)(dVar27 * (double)CONCAT44(uVar26,0x3f800000));
          if ((*(uint *)(iVar9 + 0x120) & 0xc000000) == 0) {
            fVar7 = local_f0 * fVar3 * local_e4 + fVar1 * local_ec + local_f0 * fVar2 * local_e8;
            fVar5 = fVar2 * local_e4 + -fVar3 * local_e8;
            fVar1 = local_ec * fVar3 * local_e4 + -fVar1 * local_f0 + local_ec * fVar2 * local_e8;
          }
          else {
            fVar6 = fVar1 * local_f8 - fVar2 * local_f4;
            fVar1 = fVar1 * local_f4 + fVar2 * local_f8;
            fVar2 = fVar1 * local_e8;
            fVar7 = local_f0 * fVar3 * local_e4 + fVar6 * local_ec + local_f0 * fVar2;
            fVar5 = fVar1 * local_e4 + -fVar3 * local_e8;
            fVar1 = local_ec * fVar3 * local_e4 + -fVar6 * local_f0 + local_ec * fVar2;
          }
          fVar2 = *(float *)(iVar10 + 0x2c) +
                  *(float *)(iVar10 + 0x28) * (float)(dVar30 + (double)fVar1) +
                  *(float *)(iVar10 + 0x20) * (float)(dVar32 + (double)fVar7) +
                  *(float *)(iVar10 + 0x24) * (float)(dVar31 + (double)fVar5);
          if (FLOAT_803db790 < fVar2) {
            local_c0 = (double)CONCAT44(0x43300000,uVar21 ^ 0x80000000);
            uVar21 = (uint)(((float)(local_c0 - DOUBLE_803df360) * (-fVar2 - FLOAT_803df414)) /
                           (-FLOAT_803db790 - FLOAT_803df414));
            local_c8 = (double)(longlong)(int)uVar21;
          }
          write_volatile_4(0xcc008000,(float)(dVar32 + (double)fVar7));
          write_volatile_4(0xcc008000,(float)(dVar31 + (double)fVar5));
          write_volatile_4(0xcc008000,(float)(dVar30 + (double)fVar1));
          write_volatile_1(DAT_cc008000,*(undefined *)(iVar9 + 0xac));
          write_volatile_1(DAT_cc008000,*(undefined *)(iVar9 + 0xad));
          write_volatile_1(DAT_cc008000,*(undefined *)(iVar9 + 0xae));
          write_volatile_1(DAT_cc008000,(char)uVar21);
          write_volatile_2(0xcc008000,*(undefined2 *)(iVar19 + 8));
          write_volatile_2(0xcc008000,*(undefined2 *)(iVar19 + 10));
          iVar19 = iVar19 + 0x10;
          iVar20 = iVar20 + -1;
        } while (iVar20 != 0);
      }
      iVar22 = iVar22 + 1;
      iVar9 = iVar23;
    } while (iVar22 < 0x19);
    if (DAT_803dd254 != '\0') {
      FUN_8009ad44(0);
      DAT_803dd254 = '\0';
    }
  }
  __psq_l0(auStack8,uVar24);
  __psq_l1(auStack8,uVar24);
  __psq_l0(auStack24,uVar24);
  __psq_l1(auStack24,uVar24);
  __psq_l0(auStack40,uVar24);
  __psq_l1(auStack40,uVar24);
  __psq_l0(auStack56,uVar24);
  __psq_l1(auStack56,uVar24);
  __psq_l0(auStack72,uVar24);
  __psq_l1(auStack72,uVar24);
  __psq_l0(auStack88,uVar24);
  __psq_l1(auStack88,uVar24);
  FUN_802860f4();
  return;
}

